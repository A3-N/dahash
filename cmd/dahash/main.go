package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const supportedSchema = "dahash.hash_type/v2"

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiCyan  = "\x1b[36m"
)

type Options struct {
	Verbose bool
	Input   string
}

type HashType struct {
	SchemaVersion  string                   `json:"schema_version"`
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Aliases        []string                 `json:"aliases"`
	Status         string                   `json:"status"`
	Priority       int                      `json:"priority"`
	Identification Identification           `json:"identification"`
	Match          Match                    `json:"match"`
	Extraction     Extraction               `json:"extraction"`
	Tools          map[string][]ToolDetails `json:"tools"`
}

type Identification struct {
	MaxConfidence int `json:"max_confidence"`
}

type Match struct {
	Base     int            `json:"base"`
	Total    int            `json:"total"`
	Requires []Rule         `json:"requires"`
	Evidence []Rule         `json:"evidence"`
	Variants []MatchVariant `json:"variants"`
}

// MatchVariant describes an alternate serialized form for the same hash type,
// such as native hashcat input versus a John converter output.
type MatchVariant struct {
	ID            string                   `json:"id"`
	Format        string                   `json:"format"`
	Base          int                      `json:"base"`
	Total         int                      `json:"total"`
	MaxConfidence int                      `json:"max_confidence"`
	Requires      []Rule                   `json:"requires"`
	Evidence      []Rule                   `json:"evidence"`
	Tools         map[string][]ToolDetails `json:"tools"`
}

type Rule struct {
	ID      string         `json:"id"`
	Feature string         `json:"feature"`
	Args    map[string]any `json:"args"`
	Weight  int            `json:"weight"`
}

type Extraction struct {
	Supported  bool        `json:"supported"`
	Inputs     []FileInput `json:"inputs"`
	Converters []Converter `json:"converters"`
}

type FileInput struct {
	Kind               string   `json:"kind"`
	Extensions         []string `json:"extensions"`
	ContentSignatures  []Rule   `json:"content_signatures"`
	ConverterInputRole string   `json:"converter_input_role"`
}

type Converter struct {
	Tool      string   `json:"tool"`
	Name      string   `json:"name"`
	Args      []string `json:"args"`
	Outputs   []string `json:"outputs"`
	InputRole string   `json:"input_role"`
}

type ToolDetails map[string]any

type MatchResult struct {
	Type          HashType
	Score         int
	Total         int
	MaxConfidence int
	Evidence      []string
	VariantID     string
	VariantFormat string
	Tools         map[string][]ToolDetails
}

type ExtractionResult struct {
	Type  HashType
	Input FileInput
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "usage: dahash [-v] <hash-or-file>")
		os.Exit(2)
	}

	dataDir, err := findDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	hashTypes, err := loadHashTypes(filepath.Join(dataDir, "hash-types"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(hashTypes) == 0 {
		fmt.Fprintf(os.Stderr, "no %s hash type JSON files found in %s\n", supportedSchema, filepath.Join(dataDir, "hash-types"))
		os.Exit(1)
	}

	input := opts.Input
	info, statErr := os.Stat(input)
	if statErr == nil {
		runFile(input, info, hashTypes, opts)
		return
	}

	runString(input, hashTypes, opts)
}

func parseArgs(args []string) (Options, error) {
	var opts Options
	for _, arg := range args {
		switch arg {
		case "-v", "--verbose":
			opts.Verbose = true
		case "-h", "--help":
			return opts, errors.New("usage: dahash [-v] <hash-or-file>")
		default:
			if opts.Input != "" {
				return opts, errors.New("expected exactly one hash or file input")
			}
			opts.Input = arg
		}
	}
	if opts.Input == "" {
		return opts, errors.New("missing hash or file input")
	}
	return opts, nil
}

func findDataDir() (string, error) {
	candidates := []string{}
	if env := strings.TrimSpace(os.Getenv("DAHASH_DATA")); env != "" {
		candidates = append(candidates, env)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "data"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "data"))
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(filepath.Join(candidate, "hash-types")); err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("could not find data/hash-types; run from repo root or set DAHASH_DATA")
}

func loadHashTypes(dir string) ([]HashType, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []HashType
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var ht HashType
		if err := json.Unmarshal(raw, &ht); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if ht.SchemaVersion != supportedSchema {
			continue
		}
		out = append(out, ht)
	}
	return out, nil
}

func runString(input string, hashTypes []HashType, opts Options) {
	value := strings.TrimSpace(input)
	results := identifyString(value, hashTypes)

	if opts.Verbose {
		fmt.Println("input: string")
	}
	printHashResults(results, value, opts)
}

func runFile(path string, info os.FileInfo, hashTypes []HashType, opts Options) {
	results := identifyFile(path, info, hashTypes)
	if opts.Verbose {
		fmt.Printf("input: file %s\n", path)
	}

	if len(results) > 0 {
		if opts.Verbose {
			fmt.Println("file extraction candidates:")
		}
		for i, result := range results {
			converter, ok := johnConverter(result.Type.Extraction.Converters)
			if result.Input.ConverterInputRole != "" {
				converter.InputRole = result.Input.ConverterInputRole
			}
			if opts.Verbose {
				printExtractionResult(i, result, path, opts)
			}
			if !ok {
				continue
			}

			hash, rawOutput, err := extractWithJohn(path, converter)
			if opts.Verbose {
				if rawOutput != "" {
					fmt.Printf("   converter output: %s\n", compactOutput(rawOutput))
				}
				if err != nil {
					fmt.Printf("   extraction error: %s\n", err)
				}
			}
			if err != nil {
				continue
			}

			if opts.Verbose {
				fmt.Printf("   extracted hash: %s\n", bold(hash))
			}
			matches := identifyString(hash, hashTypes)
			if len(matches) == 0 {
				matches = []MatchResult{{
					Type:     result.Type,
					Score:    0,
					Evidence: []string{"john_extraction"},
				}}
			}
			printHashResults(matches, hash, opts)
			return
		}

		if opts.Verbose {
			fmt.Println("no usable john converter extracted a hash")
		} else {
			fmt.Println("no hash extracted")
		}
		return
	}

	if !info.IsDir() {
		if text, ok := readTextCandidate(path); ok {
			if opts.Verbose {
				fmt.Println("no file extraction candidate matched; trying file contents as a hash string")
			}
			printHashResults(identifyString(text, hashTypes), text, opts)
			return
		}
	}

	fmt.Println("no file extraction candidate matched")
}

func johnConverter(converters []Converter) (Converter, bool) {
	for _, converter := range converters {
		if strings.EqualFold(converter.Tool, "john") {
			return converter, true
		}
	}
	return Converter{}, false
}

func extractWithJohn(path string, converter Converter) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	preparedPath, cleanup, err := prepareConverterInput(path, converter)
	if err != nil {
		return "", "", err
	}
	defer cleanup()

	args := renderArgList(converter.Args, preparedPath)
	cmd := exec.CommandContext(ctx, converter.Name, args...)
	output, err := cmd.CombinedOutput()
	raw := string(output)
	if hash := parseConverterHash(raw, converter.Outputs); hash != "" {
		return hash, raw, nil
	}
	if ctx.Err() != nil {
		return "", raw, fmt.Errorf("%s timed out", converter.Name)
	}
	if err != nil {
		return "", raw, fmt.Errorf("%s failed: %w", converter.Name, err)
	}
	return "", raw, fmt.Errorf("%s produced no recognized hash", converter.Name)
}

func prepareConverterInput(path string, converter Converter) (string, func(), error) {
	switch converter.InputRole {
	case "", "direct":
		return path, func() {}, nil
	case "1password_agile_encryption_keys_file":
		return stageSingleFileForJohn(path, filepath.Join("input.agilekeychain", "data", "default", "encryptionKeys.js"), "input.agilekeychain")
	case "1password_cloud_profile_file":
		return stageSingleFileForJohn(path, filepath.Join("input.opvault", "default", "profile.js"), "input.opvault")
	case "1password_sqlite_file":
		return stageSingleFileForJohn(path, "OnePassword.sqlite", "OnePassword.sqlite")
	default:
		return "", func() {}, fmt.Errorf("unsupported converter input role: %s", converter.InputRole)
	}
}

func stageSingleFileForJohn(sourcePath, relativeFile, relativeRoot string) (string, func(), error) {
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", func() {}, err
	}
	tmp, err := os.MkdirTemp("", "dahash-john-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	target := filepath.Join(tmp, relativeFile)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return filepath.Join(tmp, relativeRoot), cleanup, nil
}

func parseConverterHash(output string, markers []string) string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, marker := range markers {
			if marker == "" {
				continue
			}
			if index := strings.Index(line, marker); index >= 0 {
				return trimHashToken(line[index:])
			}
		}
	}
	return ""
}

func trimHashToken(value string) string {
	value = strings.TrimSpace(value)
	for i, r := range value {
		if r == ' ' || r == '\t' {
			return value[:i]
		}
	}
	return value
}

func identifyString(value string, hashTypes []HashType) []MatchResult {
	var results []MatchResult
	for _, ht := range hashTypes {
		if len(ht.Match.Variants) > 0 {
			for _, variant := range ht.Match.Variants {
				if result, ok := evaluateVariant(value, ht, variant); ok {
					results = append(results, result)
				}
			}
			continue
		}

		if result, ok := evaluateDefaultMatch(value, ht); ok {
			results = append(results, result)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score == results[j].Score {
			if results[i].Type.ID == results[j].Type.ID {
				return results[i].VariantID < results[j].VariantID
			}
			return results[i].Type.ID < results[j].Type.ID
		}
		return results[i].Score > results[j].Score
	})
	return results
}

func evaluateDefaultMatch(value string, ht HashType) (MatchResult, bool) {
	if ht.Match.Base == 0 && len(ht.Match.Requires) == 0 && len(ht.Match.Evidence) == 0 {
		return MatchResult{}, false
	}
	score, evidence, ok := evaluateRules(value, ht.Match.Base, ht.Match.Requires, ht.Match.Evidence)
	if !ok {
		return MatchResult{}, false
	}
	return MatchResult{Type: ht, Score: score, Total: ht.Match.Total, Evidence: evidence, Tools: ht.Tools}, true
}

func evaluateVariant(value string, ht HashType, variant MatchVariant) (MatchResult, bool) {
	score, evidence, ok := evaluateRules(value, variant.Base, variant.Requires, variant.Evidence)
	if !ok {
		return MatchResult{}, false
	}
	tools := variant.Tools
	if len(tools) == 0 {
		tools = ht.Tools
	}
	return MatchResult{
		Type:          ht,
		Score:         score,
		Total:         variant.Total,
		MaxConfidence: variant.MaxConfidence,
		Evidence:      evidence,
		VariantID:     variant.ID,
		VariantFormat: variant.Format,
		Tools:         tools,
	}, true
}

func evaluateRules(value string, base int, requires []Rule, evidenceRules []Rule) (int, []string, bool) {
	for _, rule := range requires {
		if !matchStringRule(value, rule) {
			return 0, nil, false
		}
	}

	score := base
	var evidence []string
	for _, rule := range evidenceRules {
		if matchStringRule(value, rule) {
			score += rule.Weight
			if rule.ID != "" {
				evidence = append(evidence, rule.ID)
			}
		}
	}
	return score, evidence, true
}

func identifyFile(path string, info os.FileInfo, hashTypes []HashType) []ExtractionResult {
	var results []ExtractionResult
	for _, ht := range hashTypes {
		if !ht.Extraction.Supported {
			continue
		}
		for _, input := range ht.Extraction.Inputs {
			if !fileKindMatches(input.Kind, info) {
				continue
			}
			if !extensionMatches(path, input.Extensions) {
				continue
			}
			if !contentSignaturesMatch(path, info, input.ContentSignatures) {
				continue
			}
			results = append(results, ExtractionResult{Type: ht, Input: input})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Type.ID < results[j].Type.ID
	})
	return results
}

func matchStringRule(value string, rule Rule) bool {
	switch rule.Feature {
	case "regex":
		pattern, _ := stringArg(rule.Args, "regex")
		return regexpMatch(pattern, value, rule.Args)
	case "prefix":
		prefix, _ := stringArg(rule.Args, "value")
		return strings.HasPrefix(value, prefix)
	case "segment_count":
		separator, _ := stringArg(rule.Args, "separator")
		count, _ := intArg(rule.Args, "count")
		return len(strings.Split(value, separator)) == count
	case "segment_regex":
		separator, _ := stringArg(rule.Args, "separator")
		segment, _ := intArg(rule.Args, "segment")
		pattern, _ := stringArg(rule.Args, "regex")
		parts := strings.Split(value, separator)
		return segment >= 0 && segment < len(parts) && regexpMatch(pattern, parts[segment], rule.Args)
	case "count_char":
		char, _ := stringArg(rule.Args, "value")
		count, _ := intArg(rule.Args, "count")
		return strings.Count(value, char) == count
	case "char_at":
		index, _ := intArg(rule.Args, "index")
		want, _ := stringArg(rule.Args, "value")
		return index >= 0 && index < len(value) && string(value[index]) == want
	case "field_count":
		parts := splitFields(value, rule.Args)
		if count, ok := intArg(rule.Args, "count"); ok {
			return len(parts) == count
		}
		min, _ := intArg(rule.Args, "min")
		max, hasMax := intArg(rule.Args, "max")
		if len(parts) < min {
			return false
		}
		return !hasMax || len(parts) <= max
	case "field_regex":
		parts := splitFields(value, rule.Args)
		pattern, _ := stringArg(rule.Args, "regex")
		if fields := intSliceArg(rule.Args, "fields"); len(fields) > 0 {
			for _, field := range fields {
				if field >= 0 && field < len(parts) && regexpMatch(pattern, parts[field], rule.Args) {
					return true
				}
			}
			return false
		}
		field, _ := intArg(rule.Args, "field")
		return field >= 0 && field < len(parts) && regexpMatch(pattern, parts[field], rule.Args)
	case "field_shape":
		return matchFieldShape(value, rule.Args)
	case "field_hex_length_matches_number":
		return matchFieldHexLengthMatchesNumber(value, rule.Args)
	case "field_repeating_group":
		return matchFieldRepeatingGroup(value, rule.Args)
	default:
		return false
	}
}

func matchFieldHexLengthMatchesNumber(value string, args map[string]any) bool {
	parts := splitFields(value, args)
	lengthField, _ := intArg(args, "length_field")
	if lengthField < 0 || lengthField >= len(parts) {
		return false
	}
	want, err := strconv.Atoi(parts[lengthField])
	if err != nil || want < 0 {
		return false
	}
	multiplier, ok := intArg(args, "multiplier")
	if !ok {
		multiplier = 2
	}
	fields := intSliceArg(args, "value_fields")
	if len(fields) == 0 {
		if field, ok := intArg(args, "value_field"); ok {
			fields = []int{field}
		}
	}
	for _, field := range fields {
		if field < 0 || field >= len(parts) {
			continue
		}
		candidate := parts[field]
		if len(candidate) == want*multiplier && charsetMatches(candidate, map[string]any{"charset": "hex"}) {
			return true
		}
	}
	return false
}

func matchFieldRepeatingGroup(value string, args map[string]any) bool {
	parts := splitFields(value, args)
	start, ok := intArg(args, "start")
	if !ok {
		start = 0
	}
	groupSize, ok := intArg(args, "group_size")
	if !ok || groupSize <= 0 || start < 0 || start > len(parts) {
		return false
	}
	remaining := len(parts) - start
	if remaining < 0 || remaining%groupSize != 0 {
		return false
	}
	groups := remaining / groupSize
	if minGroups, ok := intArg(args, "min_groups"); ok && groups < minGroups {
		return false
	}
	if maxGroups, ok := intArg(args, "max_groups"); ok && groups > maxGroups {
		return false
	}
	if countField, ok := intArg(args, "count_field"); ok {
		if countField < 0 || countField >= len(parts) {
			return false
		}
		countText := parts[countField]
		if prefix, ok := stringArg(args, "count_field_optional_prefix"); ok && strings.HasPrefix(countText, prefix) {
			countText = strings.TrimPrefix(countText, prefix)
		}
		wantGroups, err := strconv.Atoi(countText)
		if err != nil || wantGroups != groups {
			return false
		}
	}

	shapes := mapSliceArg(args, "shapes")
	for group := 0; group < groups; group++ {
		base := start + group*groupSize
		for _, shape := range shapes {
			offset, ok := intArg(shape, "offset")
			if !ok || offset < 0 || offset >= groupSize {
				return false
			}
			fieldIndex := base + offset
			if fieldIndex >= len(parts) {
				return false
			}
			if refOffset, ok := intArg(shape, "length_from_offset"); ok {
				if refOffset < 0 || refOffset >= groupSize {
					return false
				}
				refIndex := base + refOffset
				want, err := strconv.Atoi(parts[refIndex])
				if err != nil || want < 0 {
					return false
				}
				multiplier, ok := intArg(shape, "multiplier")
				if !ok {
					multiplier = 2
				}
				if len(parts[fieldIndex]) != want*multiplier {
					return false
				}
			}
			if !shapeMatches(parts[fieldIndex], shape) {
				return false
			}
		}
	}
	return true
}

func matchFieldShape(value string, args map[string]any) bool {
	parts := splitFields(value, args)
	if fields := intSliceArg(args, "fields"); len(fields) > 0 {
		for _, field := range fields {
			if field >= 0 && field < len(parts) && shapeMatches(parts[field], args) {
				return true
			}
		}
		return false
	}
	field, _ := intArg(args, "field")
	return field >= 0 && field < len(parts) && shapeMatches(parts[field], args)
}

func shapeMatches(value string, args map[string]any) bool {
	if optionalPrefix, ok := stringArg(args, "optional_prefix"); ok && strings.HasPrefix(value, optionalPrefix) {
		value = strings.TrimPrefix(value, optionalPrefix)
	}
	for _, optionalPrefix := range stringSliceArg(args, "optional_prefixes") {
		if strings.HasPrefix(value, optionalPrefix) {
			value = strings.TrimPrefix(value, optionalPrefix)
			break
		}
	}
	if prefix, ok := stringArg(args, "prefix"); ok {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = strings.TrimPrefix(value, prefix)
	}
	if suffix, ok := stringArg(args, "suffix"); ok {
		if !strings.HasSuffix(value, suffix) {
			return false
		}
		value = strings.TrimSuffix(value, suffix)
	}
	if !lengthMatches(len(value), args) {
		return false
	}
	if !charsetMatches(value, args) {
		return false
	}
	if min, ok := intArg(args, "numeric_min"); ok || hasArg(args, "numeric_max") {
		if value == "" {
			return false
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		if ok && n < int64(min) {
			return false
		}
		if max, ok := intArg(args, "numeric_max"); ok && n > int64(max) {
			return false
		}
	}
	return true
}

func lengthMatches(length int, args map[string]any) bool {
	if exact, ok := intArg(args, "length"); ok {
		return length == exact
	}
	if exact, ok := intArg(args, "length_exact"); ok {
		return length == exact
	}
	if min, ok := intArg(args, "length_min"); ok && length < min {
		return false
	}
	if max, ok := intArg(args, "length_max"); ok && length > max {
		return false
	}
	if multiple, ok := intArg(args, "length_multiple_of"); ok && multiple > 0 && length%multiple != 0 {
		return false
	}
	return true
}

func charsetMatches(value string, args map[string]any) bool {
	charset, _ := stringArg(args, "charset")
	switch charset {
	case "", "any":
		return true
	case "hex":
		for _, r := range value {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
		return true
	case "decimal":
		for _, r := range value {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	case "alnum_dot_slash":
		for _, r := range value {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '.' || r == '/') {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func splitFields(value string, args map[string]any) []string {
	separator, _ := stringArg(args, "separator")
	parts := strings.Split(value, separator)
	if trim, _ := boolArg(args, "trim_empty_start"); trim && len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	if marker, ok := stringArg(args, "drop_prefix_field"); ok && len(parts) > 0 && strings.EqualFold(parts[0], marker) {
		parts = parts[1:]
	}
	return parts
}

func regexpMatch(pattern, value string, args map[string]any) bool {
	if pattern == "" {
		return false
	}
	pattern = normalizePattern(pattern)
	if hasFlag(args, "i") {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func normalizePattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `\A`, `^`)
	pattern = strings.ReplaceAll(pattern, `\Z`, `$`)
	pattern = strings.ReplaceAll(pattern, `\d`, `[0-9]`)
	pattern = regexp.MustCompile(`\{,([0-9]+)\}`).ReplaceAllString(pattern, `{0,$1}`)
	pattern = relaxLargeRangeRepeats(pattern)
	pattern = expandLargeOpenRepeats(pattern)
	return expandLargeExactRepeats(pattern)
}

func relaxLargeRangeRepeats(pattern string) string {
	re := regexp.MustCompile(`(\[[^\]]+\]|\\.|.)\{([0-9]+),([0-9]+)\}`)
	return re.ReplaceAllStringFunc(pattern, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		max, err := strconv.Atoi(parts[3])
		if err != nil || max <= 1000 {
			return match
		}
		return parts[1] + "{" + parts[2] + ",}"
	})
}

func expandLargeOpenRepeats(pattern string) string {
	re := regexp.MustCompile(`(\[[^\]]+\]|\\.|.)\{([0-9]+),\}`)
	return re.ReplaceAllStringFunc(pattern, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		min, err := strconv.Atoi(parts[2])
		if err != nil || min <= 1000 {
			return match
		}
		atom := parts[1]
		var b strings.Builder
		for min > 1000 {
			b.WriteString(atom)
			b.WriteString("{1000}")
			min -= 1000
		}
		b.WriteString(atom)
		b.WriteString("{")
		b.WriteString(strconv.Itoa(min))
		b.WriteString(",}")
		return b.String()
	})
}

func expandLargeExactRepeats(pattern string) string {
	re := regexp.MustCompile(`(\[[^\]]+\]|\\.|.)\{([0-9]+)\}`)
	return re.ReplaceAllStringFunc(pattern, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		count, err := strconv.Atoi(parts[2])
		if err != nil || count <= 1000 {
			return match
		}
		atom := parts[1]
		var b strings.Builder
		for count > 1000 {
			b.WriteString(atom)
			b.WriteString("{1000}")
			count -= 1000
		}
		if count > 0 {
			b.WriteString(atom)
			b.WriteString("{")
			b.WriteString(strconv.Itoa(count))
			b.WriteString("}")
		}
		return b.String()
	})
}

func fileKindMatches(kind string, info os.FileInfo) bool {
	switch kind {
	case "directory":
		return info.IsDir()
	case "file", "archive", "split_archive", "self_extracting_archive":
		return !info.IsDir()
	default:
		return true
	}
}

func extensionMatches(path string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}
	lower := strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func contentSignaturesMatch(path string, info os.FileInfo, signatures []Rule) bool {
	for _, sig := range signatures {
		if !matchContentSignature(path, info, sig) {
			return false
		}
	}
	return true
}

func matchContentSignature(path string, info os.FileInfo, sig Rule) bool {
	switch sig.Feature {
	case "magic":
		if info.IsDir() {
			return false
		}
		return matchMagic(path, sig.Args)
	case "embedded_magic":
		if info.IsDir() {
			return false
		}
		return matchEmbeddedMagic(path, sig.Args)
	case "contains_entry_name":
		if !info.IsDir() {
			return false
		}
		name, _ := stringArg(sig.Args, "name")
		return directoryContainsEntryName(path, name)
	case "contains_json_keys":
		return pathContainsJSONKeys(path, info, stringSliceArg(sig.Args, "keys"))
	case "contains_json_array_item_keys":
		keys := stringSliceArg(sig.Args, "keys")
		keys = append(keys, stringArgOrEmpty(sig.Args, "array"))
		return pathContainsJSONKeys(path, info, keys)
	case "sqlite_table_columns":
		if info.IsDir() {
			return false
		}
		return fileContainsAll(path, append([]string{stringArgOrEmpty(sig.Args, "table")}, stringSliceArg(sig.Args, "columns")...))
	default:
		return false
	}
}

func matchMagic(path string, args map[string]any) bool {
	offset, _ := intArg(args, "offset")
	want, ok := bytesFromArgs(args)
	if !ok {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, len(want))
	if _, err := file.ReadAt(buf, int64(offset)); err != nil {
		return false
	}
	return bytes.Equal(buf, want)
}

func matchEmbeddedMagic(path string, args map[string]any) bool {
	want, ok := bytesFromArgs(args)
	if !ok {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(raw, want)
}

func bytesFromArgs(args map[string]any) ([]byte, bool) {
	if hexValue, ok := stringArg(args, "hex"); ok {
		compact := strings.ReplaceAll(hexValue, " ", "")
		out, err := hex.DecodeString(compact)
		return out, err == nil
	}
	if ascii, ok := stringArg(args, "ascii"); ok {
		return []byte(ascii), true
	}
	return nil, false
}

func directoryContainsEntryName(root, name string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.Name() == name {
			found = true
		}
		return nil
	})
	return found
}

func pathContainsJSONKeys(path string, info os.FileInfo, keys []string) bool {
	if info.IsDir() {
		return directoryContainsJSONKeys(path, keys)
	}
	return fileContainsJSONKeys(path, keys)
}

func directoryContainsJSONKeys(root string, keys []string) bool {
	if len(keys) == 0 {
		return true
	}
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Size() > 2*1024*1024 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(raw)
		for _, key := range keys {
			if key == "" {
				continue
			}
			if !strings.Contains(text, strconv.Quote(key)) && !strings.Contains(text, key) {
				return nil
			}
		}
		found = true
		return nil
	})
	return found
}

func fileContainsJSONKeys(path string, keys []string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(raw)
	for _, key := range keys {
		if key == "" {
			continue
		}
		if !strings.Contains(text, strconv.Quote(key)) && !strings.Contains(text, key) {
			return false
		}
	}
	return true
}

func fileContainsAll(path string, values []string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if !bytes.Contains(raw, []byte(value)) {
			return false
		}
	}
	return true
}

func readTextCandidate(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1024*1024 || bytes.Contains(raw, []byte{0}) || !utf8.Valid(raw) {
		return "", false
	}
	text := strings.TrimSpace(string(raw))
	return text, text != ""
}

func printHashResults(results []MatchResult, value string, opts Options) {
	if len(results) == 0 {
		fmt.Println("no hash candidates matched")
		return
	}

	for i, result := range results {
		if i > 0 {
			fmt.Println()
		}
		printHashResult(i, result, value, opts)
	}
}

func printHashResult(index int, result MatchResult, value string, opts Options) {
	confidence := confidencePercent(result)
	if opts.Verbose {
		fmt.Printf("%d. %s (%s) %s score=%s\n", index+1, cyan(result.Type.Name), cyan(result.Type.ID), bold(confidence), bold(strconv.Itoa(result.Score)))
		fmt.Printf("   %s\n", bold(value))
		if len(result.Evidence) > 0 {
			fmt.Printf("   evidence: %s\n", strings.Join(result.Evidence, ", "))
		}
		printTools(resultTools(result), "   ")
		return
	}

	fmt.Printf("%s (%s) %s\n", cyan(result.Type.Name), cyan(result.Type.ID), bold(confidence))
	fmt.Println(bold(value))
	printTools(resultTools(result), "")
}

func resultTools(result MatchResult) map[string][]ToolDetails {
	if len(result.Tools) > 0 {
		return result.Tools
	}
	return result.Type.Tools
}

func confidencePercent(result MatchResult) string {
	total := result.Total
	if total <= 0 {
		total = result.Type.Match.Total
	}
	if total <= 0 {
		total = result.Type.Match.Base
		for _, rule := range result.Type.Match.Evidence {
			total += rule.Weight
		}
	}
	if total <= 0 || result.Score <= 0 {
		return "0%"
	}
	percent := result.Score * 100 / total
	if percent > 99 {
		percent = 99
	}
	if max := result.MaxConfidence; max > 0 && percent > max {
		percent = max
	}
	if max := result.Type.Identification.MaxConfidence; max > 0 && percent > max {
		percent = max
	}
	return strconv.Itoa(percent) + "%"
}

func printExtractionResult(index int, result ExtractionResult, path string, opts Options) {
	if opts.Verbose {
		fmt.Printf("%d. %s (%s) %s\n", index+1, cyan(result.Type.Name), cyan(result.Type.ID), bold(path))
		fmt.Printf("   input kind: %s\n", result.Input.Kind)
		if len(result.Input.Extensions) > 0 {
			fmt.Printf("   extensions: %s\n", strings.Join(result.Input.Extensions, ", "))
		}
		if len(result.Type.Extraction.Converters) > 0 {
			fmt.Println("   converters:")
			for _, converter := range result.Type.Extraction.Converters {
				fmt.Printf("   - %s %s %s\n", converter.Tool, converter.Name, renderArgs(converter.Args, path))
			}
		}
		printTools(result.Type.Tools, "   ")
		return
	}

	fmt.Printf("%s (%s)\n", cyan(result.Type.Name), cyan(result.Type.ID))
	fmt.Println(bold(path))
	printTools(result.Type.Tools, "")
}

func printTools(tools map[string][]ToolDetails, prefix string) {
	if len(tools) == 0 {
		return
	}
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, details := range tools[name] {
			switch name {
			case "hashcat":
				if mode, ok := numericToolValue(details, "mode"); ok {
					fmt.Printf("%shashcat mode %s\n", prefix, bold(mode))
				}
			case "john":
				if format, ok := stringToolValue(details, "format"); ok {
					fmt.Printf("%sjohn format %s\n", prefix, bold(format))
				}
			default:
				fmt.Printf("%s%s\n", prefix, name)
			}
		}
	}
}

func bold(value string) string {
	return ansiBold + value + ansiReset
}

func cyan(value string) string {
	return ansiCyan + value + ansiReset
}

func renderArgs(args []string, input string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(renderArgList(args, input), " ")
}

func renderArgList(args []string, input string) []string {
	rendered := make([]string, len(args))
	for i, arg := range args {
		rendered[i] = strings.ReplaceAll(arg, "{input}", input)
	}
	return rendered
}

func compactOutput(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	compact := strings.Join(fields, " ")
	if len(compact) > 240 {
		return compact[:240] + "..."
	}
	return compact
}

func hasFlag(args map[string]any, flag string) bool {
	flags, ok := args["flags"].([]any)
	if !ok {
		return false
	}
	for _, value := range flags {
		if s, ok := value.(string); ok && s == flag {
			return true
		}
	}
	return false
}

func stringArg(args map[string]any, key string) (string, bool) {
	value, ok := args[key].(string)
	return value, ok
}

func stringArgOrEmpty(args map[string]any, key string) string {
	value, _ := stringArg(args, key)
	return value
}

func intArg(args map[string]any, key string) (int, bool) {
	switch value := args[key].(type) {
	case float64:
		return int(value), true
	case int:
		return value, true
	default:
		return 0, false
	}
}

func boolArg(args map[string]any, key string) (bool, bool) {
	value, ok := args[key].(bool)
	return value, ok
}

func hasArg(args map[string]any, key string) bool {
	_, ok := args[key]
	return ok
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func intSliceArg(args map[string]any, key string) []int {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(raw))
	for _, value := range raw {
		switch v := value.(type) {
		case float64:
			out = append(out, int(v))
		case int:
			out = append(out, v)
		}
	}
	return out
}

func mapSliceArg(args map[string]any, key string) []map[string]any {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if m, ok := value.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func stringToolValue(details ToolDetails, key string) (string, bool) {
	value, ok := details[key].(string)
	return value, ok
}

func numericToolValue(details ToolDetails, key string) (string, bool) {
	switch value := details[key].(type) {
	case float64:
		return strconv.Itoa(int(value)), true
	case int:
		return strconv.Itoa(value), true
	default:
		return "", false
	}
}
