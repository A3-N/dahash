package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"dahash/pkg/matcher"
	"dahash/pkg/schema"
)

const johnRunURL = "https://github.com/openwall/john/tree/bleeding-jumbo/run"

type options struct {
	showExamples bool
	showHashcat  bool
	showJohn     bool
	jsonDataDir  string
	input        string
	filePath     string
}

type fileConverterCatalog struct {
	SchemaVersion string          `json:"schema_version"`
	Converters    []fileConverter `json:"converters"`
}

type fileConverter struct {
	ID         string          `json:"id"`
	Extensions []string        `json:"extensions,omitempty"`
	Tools      []converterTool `json:"tools"`
	Notes      string          `json:"notes,omitempty"`
}

type converterTool struct {
	Name              string   `json:"name"`
	Args              []string `json:"args,omitempty"`
	ExpectedHashTypes []string `json:"expected_hash_types,omitempty"`
}

type fileConversion struct {
	FilePath    string
	ConverterID string
	ToolName    string
	HashLine    string
	Results     []matcher.Result
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, input, err := parse(args, stderr)
	if err != nil {
		return err
	}
	if opts.filePath != "" && input != "" {
		return fmt.Errorf("use either a hash input or --file, not both")
	}
	sourcesPath := filepath.Join(opts.jsonDataDir, "sources.json")
	hashTypesDir := filepath.Join(opts.jsonDataDir, "hash-types")
	catalog, err := schema.LoadCatalogFromDirectory(sourcesPath, hashTypesDir)
	if err != nil {
		return err
	}
	engine, err := matcher.New(catalog)
	if err != nil {
		return err
	}
	var results []matcher.Result
	if opts.filePath != "" {
		conversion, err := convertFileHash(opts.filePath, opts.jsonDataDir, engine)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "File: %s\n", conversion.FilePath)
		fmt.Fprintf(stdout, "Converter: %s (%s)\n\n", conversion.ToolName, conversion.ConverterID)
		input = conversion.HashLine
		results = conversion.Results
	} else {
		if input == "" {
			input, err = promptForHash(stdin, stdout)
			if err != nil {
				return err
			}
		}
		results = engine.Identify(input)
	}
	printResults(stdout, input, results, opts)
	return nil
}

func parse(args []string, stderr io.Writer) (options, string, error) {
	opts := options{jsonDataDir: "data"}
	args = stripIdentifyCommand(args)
	fs := flag.NewFlagSet("dahash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.showExamples, "e", false, "show examples and matcher reasons")
	fs.BoolVar(&opts.showExamples, "examples", false, "show examples and matcher reasons")
	fs.BoolVar(&opts.showHashcat, "h", false, "show Hashcat crack command templates")
	fs.BoolVar(&opts.showHashcat, "hashcat", false, "show Hashcat crack command templates")
	fs.BoolVar(&opts.showJohn, "j", false, "show John the Ripper crack command templates")
	fs.BoolVar(&opts.showJohn, "john", false, "show John the Ripper crack command templates")
	fs.StringVar(&opts.jsonDataDir, "data", "data", "directory containing sources.json and hash-types/")
	fs.StringVar(&opts.input, "i", "", "hash input to identify")
	fs.StringVar(&opts.filePath, "f", "", "file to convert with an explicit John helper before identifying")
	fs.StringVar(&opts.filePath, "file", "", "file to convert with an explicit John helper before identifying")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  dahash identify [flags] [hash]")
		fmt.Fprintln(stderr, "  dahash [flags] <hash>")
		fmt.Fprintln(stderr, "  dahash -i <hash> [flags]")
		fmt.Fprintln(stderr, "  dahash -f <file> [flags]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
	}
	for _, arg := range args {
		if arg == "--help" {
			fs.Usage()
			return opts, "", flag.ErrHelp
		}
	}
	if err := fs.Parse(args); err != nil {
		return opts, "", err
	}
	input := strings.TrimSpace(opts.input)
	if input == "" {
		remaining := stripIdentifyCommand(fs.Args())
		input = strings.TrimSpace(strings.Join(remaining, " "))
	}
	return opts, input, nil
}

func stripIdentifyCommand(args []string) []string {
	if len(args) > 0 && args[0] == "identify" {
		return args[1:]
	}
	return args
}

func promptForHash(stdin io.Reader, stdout io.Writer) (string, error) {
	fmt.Fprint(stdout, "Hash: ")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	input := strings.TrimSpace(line)
	if input == "" {
		return "", fmt.Errorf("missing hash input")
	}
	return input, nil
}

func convertFileHash(path string, dataDir string, engine *matcher.Engine) (fileConversion, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return fileConversion{}, fmt.Errorf("missing file path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fileConversion{}, err
	}
	if info.IsDir() {
		return fileConversion{}, fmt.Errorf("%s is a directory", path)
	}
	catalog, err := loadFileConverterCatalog(filepath.Join(dataDir, "file-converters.json"))
	if err != nil {
		return fileConversion{}, err
	}
	converters := catalog.convertersForPath(path)
	if len(converters) == 0 {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" {
			ext = "<none>"
		}
		return fileConversion{}, fmt.Errorf("unsupported file extension %s; dahash only converts explicit John-supported file types and skips generic formats like .txt", ext)
	}

	missingTools := make([]string, 0)
	failures := make([]string, 0)
	for _, converter := range converters {
		for _, tool := range converter.Tools {
			toolPath, err := exec.LookPath(tool.Name)
			if err != nil {
				missingTools = append(missingTools, tool.Name)
				continue
			}
			stdout, stderr, err := runConverterTool(toolPath, tool, path)
			hashLine, results := firstIdentifiedConverterLine(stdout, engine, tool.ExpectedHashTypes)
			if hashLine != "" {
				return fileConversion{
					FilePath:    path,
					ConverterID: converter.ID,
					ToolName:    tool.Name,
					HashLine:    hashLine,
					Results:     results,
				}, nil
			}
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s failed: %v %s", tool.Name, err, strings.TrimSpace(stderr)))
				continue
			}
			failures = append(failures, fmt.Sprintf("%s produced no identifiable hash", tool.Name))
		}
	}
	if len(missingTools) > 0 && len(failures) == 0 {
		return fileConversion{}, fmt.Errorf("no supported John converter found in PATH for %s; tried %s. Install John jumbo run helpers from %s and put them on PATH", filepath.Ext(path), strings.Join(uniqueStrings(missingTools), ", "), johnRunURL)
	}
	if len(missingTools) > 0 {
		failures = append(failures, "missing tools: "+strings.Join(uniqueStrings(missingTools), ", "))
	}
	return fileConversion{}, fmt.Errorf("no converter produced an identifiable hash for %s. %s. Get John jumbo helpers from %s", path, strings.Join(failures, "; "), johnRunURL)
}

func loadFileConverterCatalog(path string) (fileConverterCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fileConverterCatalog{}, err
	}
	var catalog fileConverterCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return fileConverterCatalog{}, err
	}
	return catalog, nil
}

func (catalog fileConverterCatalog) convertersForPath(path string) []fileConverter {
	ext := strings.ToLower(filepath.Ext(path))
	matches := make([]fileConverter, 0)
	for _, converter := range catalog.Converters {
		for _, candidate := range converter.Extensions {
			if strings.ToLower(candidate) == ext {
				matches = append(matches, converter)
				break
			}
		}
	}
	return matches
}

func runConverterTool(toolPath string, tool converterTool, filePath string) (string, string, error) {
	args := make([]string, 0, len(tool.Args))
	for _, arg := range tool.Args {
		args = append(args, strings.ReplaceAll(arg, "{file}", filePath))
	}
	commandPath, commandArgs := converterCommand(toolPath, tool.Name, args)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, commandPath, commandArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after 60s")
	}
	return stdout.String(), stderr.String(), err
}

func converterCommand(toolPath string, toolName string, args []string) (string, []string) {
	ext := strings.ToLower(filepath.Ext(toolName))
	switch ext {
	case ".py":
		if python, err := exec.LookPath("python3"); err == nil {
			return python, append([]string{toolPath}, args...)
		}
		if python, err := exec.LookPath("python"); err == nil {
			return python, append([]string{toolPath}, args...)
		}
	case ".pl":
		if perl, err := exec.LookPath("perl"); err == nil {
			return perl, append([]string{toolPath}, args...)
		}
	}
	return toolPath, args
}

func firstIdentifiedConverterLine(output string, engine *matcher.Engine, expectedHashTypes []string) (string, []matcher.Result) {
	for _, line := range strings.Split(output, "\n") {
		for _, candidate := range converterLineCandidates(line) {
			results := engine.Identify(candidate)
			results = filterExpectedResults(results, expectedHashTypes)
			if len(results) > 0 {
				return candidate, results
			}
		}
	}
	return "", nil
}

func converterLineCandidates(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	candidates := []string{line}
	if idx := strings.Index(line, "$"); idx > 0 {
		candidates = append(candidates, strings.TrimSpace(line[idx:]))
	}
	if idx := strings.LastIndex(line, ":"); idx >= 0 && idx < len(line)-1 {
		candidates = append(candidates, strings.TrimSpace(line[idx+1:]))
	}
	if idx := strings.Index(line, ":"); idx >= 0 && idx < len(line)-1 {
		candidates = append(candidates, strings.TrimSpace(line[idx+1:]))
	}
	return uniqueStrings(candidates)
}

func filterExpectedResults(results []matcher.Result, expectedHashTypes []string) []matcher.Result {
	if len(results) == 0 || len(expectedHashTypes) == 0 {
		return results
	}
	expected := make(map[string]struct{}, len(expectedHashTypes))
	for _, id := range expectedHashTypes {
		expected[id] = struct{}{}
	}
	filtered := make([]matcher.Result, 0, len(results))
	for _, result := range results {
		if _, ok := expected[result.HashType.ID]; ok {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func printResults(w io.Writer, input string, results []matcher.Result, opts options) {
	fmt.Fprintf(w, "%s\n\n", input)
	if len(results) == 0 {
		fmt.Fprintln(w, "No matches.")
		return
	}
	topScore := results[0].Score
	printedAlsoPossible := false
	for i := 0; i < len(results); i++ {
		result := results[i]
		if i == 0 {
			fmt.Fprintln(w, "Likely")
		}
		if result.Score < topScore && !printedAlsoPossible {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Also possible")
			printedAlsoPossible = true
		}
		fmt.Fprintf(w, "[%d] %s", i+1, result.HashType.Name)
		if result.HashType.ID != "" {
			fmt.Fprintf(w, " (%s)", result.HashType.ID)
		}
		fmt.Fprintf(w, " score=%d", result.Score)
		if len(result.Matchers) > 0 {
			fmt.Fprintf(w, " confidence=%s", result.Matchers[0].Confidence)
		}
		fmt.Fprintln(w)
		printToolSummary(w, result.HashType)
		if opts.showExamples {
			printExamples(w, result)
		}
		if opts.showHashcat {
			printHashcatCommands(w, input, result.HashType)
		}
		if opts.showJohn {
			printJohnCommands(w, input, result.HashType)
		}
		fmt.Fprintln(w)
	}
}

func printToolSummary(w io.Writer, hashType schema.HashType) {
	if len(hashType.Tools.Hashcat) > 0 {
		parts := make([]string, 0, len(hashType.Tools.Hashcat))
		for _, ref := range hashType.Tools.Hashcat {
			parts = append(parts, fmt.Sprintf("%d", ref.Mode))
		}
		fmt.Fprintf(w, "    Hashcat: %s\n", strings.Join(parts, ", "))
	}
	if len(hashType.Tools.John) > 0 {
		parts := make([]string, 0, len(hashType.Tools.John))
		for _, ref := range hashType.Tools.John {
			parts = append(parts, ref.Format)
		}
		fmt.Fprintf(w, "    John: %s\n", strings.Join(parts, ", "))
	}
}

func printExamples(w io.Writer, result matcher.Result) {
	for _, match := range result.Matchers {
		fmt.Fprintf(w, "    Reason: %s matcher %s", match.Kind, match.ID)
		if match.Pattern != "" {
			fmt.Fprintf(w, " matched %s", match.Pattern)
		}
		fmt.Fprintln(w)
	}
	if len(result.HashType.Examples) == 0 {
		return
	}
	maxExamples := 3
	if len(result.HashType.Examples) < maxExamples {
		maxExamples = len(result.HashType.Examples)
	}
	for i := 0; i < maxExamples; i++ {
		example := result.HashType.Examples[i]
		fmt.Fprintf(w, "    Example hash: %s", example.Value)
		if example.Plaintext != "" {
			fmt.Fprintf(w, " plaintext=%s", example.Plaintext)
		}
		fmt.Fprintln(w)
	}
}

func printHashcatCommands(w io.Writer, input string, hashType schema.HashType) {
	for _, ref := range hashType.Tools.Hashcat {
		fmt.Fprintf(w, "    Hashcat command: hashcat -m %d %s <wordlist>\n", ref.Mode, shellQuote(input))
	}
}

func printJohnCommands(w io.Writer, input string, hashType schema.HashType) {
	for _, ref := range hashType.Tools.John {
		fmt.Fprintf(w, "    John command: printf '%%s\\n' %s > dahash.hash && john --format=%s dahash.hash --wordlist=<wordlist>\n", shellQuote(input), ref.Format)
	}
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
