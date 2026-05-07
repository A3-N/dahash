package schema

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)

// ValidationError contains all schema validation failures.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "schema validation failed"
	}
	return "schema validation failed: " + strings.Join(e.Problems, "; ")
}

func (e *ValidationError) add(format string, args ...any) {
	e.Problems = append(e.Problems, fmt.Sprintf(format, args...))
}

func (e *ValidationError) err() error {
	if len(e.Problems) == 0 {
		return nil
	}
	return e
}

// Validate verifies structural invariants and matcher syntax.
func (c Catalog) Validate() error {
	var verr ValidationError
	if c.SchemaVersion == "" {
		verr.add("catalog.schema_version is required")
	}
	sourceIDs := make(map[string]struct{}, len(c.Sources))
	for i, source := range c.Sources {
		validateID(&verr, fmt.Sprintf("catalog.sources[%d].id", i), source.ID)
		if source.Name == "" {
			verr.add("catalog.sources[%d].name is required", i)
		}
		if source.URL != "" && !isURL(source.URL) {
			verr.add("catalog.sources[%d].url is not a valid URL", i)
		}
		if source.ID != "" {
			if _, exists := sourceIDs[source.ID]; exists {
				verr.add("catalog.sources[%d].id %q is duplicated", i, source.ID)
			}
			sourceIDs[source.ID] = struct{}{}
		}
	}
	hashIDs := make(map[string]struct{}, len(c.HashTypes))
	for i, hashType := range c.HashTypes {
		validateHashType(&verr, sourceIDs, hashIDs, i, hashType)
	}
	return verr.err()
}

func validateHashType(verr *ValidationError, sourceIDs, hashIDs map[string]struct{}, index int, hashType HashType) {
	path := fmt.Sprintf("catalog.hash_types[%d]", index)
	validateID(verr, path+".id", hashType.ID)
	if hashType.ID != "" {
		if _, exists := hashIDs[hashType.ID]; exists {
			verr.add("%s.id %q is duplicated", path, hashType.ID)
		}
		hashIDs[hashType.ID] = struct{}{}
	}
	if hashType.Name == "" {
		verr.add("%s.name is required", path)
	}
	if !validStatus(hashType.Status) {
		verr.add("%s.status %q is invalid", path, hashType.Status)
	}
	for i, matcher := range hashType.Matchers {
		validateMatcher(verr, sourceIDs, fmt.Sprintf("%s.matchers[%d]", path, i), matcher)
	}
	validateToolRefs(verr, sourceIDs, path+".tools", hashType.Tools)
	for i, example := range hashType.Examples {
		validateExample(verr, sourceIDs, fmt.Sprintf("%s.examples[%d]", path, i), example)
	}
	for i, observation := range hashType.Observations {
		validateObservation(verr, sourceIDs, fmt.Sprintf("%s.observations[%d]", path, i), observation)
	}
	for i, ref := range hashType.Sources {
		validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.sources[%d]", path, i), ref)
	}
	for i, relation := range hashType.Relations {
		if relation.Kind == "" {
			verr.add("%s.relations[%d].kind is required", path, i)
		}
		if relation.Target == "" {
			verr.add("%s.relations[%d].target is required", path, i)
		}
	}
}

func validateMatcher(verr *ValidationError, sourceIDs map[string]struct{}, path string, matcher Matcher) {
	if matcher.Kind == "" {
		verr.add("%s.kind is required", path)
	}
	switch matcher.Kind {
	case MatcherRegex:
		if matcher.Pattern == "" {
			verr.add("%s.pattern is required for regex matcher", path)
		} else if _, err := regexp.Compile(matcher.Pattern); err != nil {
			verr.add("%s.pattern is not a valid Go regexp: %v", path, err)
		}
	case MatcherParser, MatcherPrefix, MatcherSuffix, MatcherContains, MatcherLength, MatcherComposite:
		if matcher.Pattern == "" && len(matcher.Characteristics) == 0 {
			verr.add("%s needs pattern or characteristics", path)
		}
	default:
		verr.add("%s.kind %q is invalid", path, matcher.Kind)
	}
	if !validConfidence(matcher.Confidence) {
		verr.add("%s.confidence %q is invalid", path, matcher.Confidence)
	}
	for i, characteristic := range matcher.Characteristics {
		validateCharacteristic(verr, fmt.Sprintf("%s.characteristics[%d]", path, i), characteristic)
	}
	for i, ref := range matcher.Sources {
		validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.sources[%d]", path, i), ref)
	}
}

func validateToolRefs(verr *ValidationError, sourceIDs map[string]struct{}, path string, tools ToolRefs) {
	for i, ref := range tools.Hashcat {
		if ref.Mode < 0 {
			verr.add("%s.hashcat[%d].mode must be >= 0", path, i)
		}
		if !validStatus(ref.Status) {
			verr.add("%s.hashcat[%d].status %q is invalid", path, i, ref.Status)
		}
		for j, source := range ref.Sources {
			validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.hashcat[%d].sources[%d]", path, i, j), source)
		}
	}
	for i, ref := range tools.John {
		if ref.Format == "" {
			verr.add("%s.john[%d].format is required", path, i)
		}
		if !validStatus(ref.Status) {
			verr.add("%s.john[%d].status %q is invalid", path, i, ref.Status)
		}
		for j, source := range ref.Sources {
			validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.john[%d].sources[%d]", path, i, j), source)
		}
	}
	for i, ref := range tools.Extractors {
		if ref.Name == "" {
			verr.add("%s.extractors[%d].name is required", path, i)
		}
		for j, source := range ref.Sources {
			validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.extractors[%d].sources[%d]", path, i, j), source)
		}
	}
}

func validateExample(verr *ValidationError, sourceIDs map[string]struct{}, path string, example Example) {
	if example.Kind == "" {
		verr.add("%s.kind is required", path)
	}
	if example.Value == "" {
		verr.add("%s.value is required", path)
	}
	if example.Kind == ExampleURL && example.Value != "" && !isURL(example.Value) {
		verr.add("%s.value is not a valid URL", path)
	}
	for i, ref := range example.Sources {
		validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.sources[%d]", path, i), ref)
	}
}

func validateObservation(verr *ValidationError, sourceIDs map[string]struct{}, path string, observation Observation) {
	if observation.Value == "" && len(observation.Characteristics) == 0 {
		verr.add("%s needs value or characteristics", path)
	}
	for i, characteristic := range observation.Characteristics {
		validateCharacteristic(verr, fmt.Sprintf("%s.characteristics[%d]", path, i), characteristic)
	}
	for i, ref := range observation.Sources {
		validateSourceRef(verr, sourceIDs, fmt.Sprintf("%s.sources[%d]", path, i), ref)
	}
}

func validateCharacteristic(verr *ValidationError, path string, characteristic Characteristic) {
	if characteristic.Kind == "" {
		verr.add("%s.kind is required", path)
	}
	if characteristic.Min != nil && characteristic.Max != nil && *characteristic.Min > *characteristic.Max {
		verr.add("%s.min must be <= max", path)
	}
	if !validConfidence(characteristic.Confidence) {
		verr.add("%s.confidence %q is invalid", path, characteristic.Confidence)
	}
}

func validateSourceRef(verr *ValidationError, sourceIDs map[string]struct{}, path string, ref SourceRef) {
	if ref.ID == "" {
		verr.add("%s.id is required", path)
		return
	}
	if len(sourceIDs) > 0 {
		if _, exists := sourceIDs[ref.ID]; !exists {
			verr.add("%s.id %q does not reference a known source", path, ref.ID)
		}
	}
}

func validateID(verr *ValidationError, path, id string) {
	if id == "" {
		verr.add("%s is required", path)
		return
	}
	if !idPattern.MatchString(id) {
		verr.add("%s %q must match %s", path, id, idPattern.String())
	}
}

func validStatus(status Status) bool {
	switch status {
	case "", StatusActive, StatusLegacy, StatusDeprecated, StatusSuperseded, StatusUnknown:
		return true
	default:
		return false
	}
}

func validConfidence(confidence ConfidenceClass) bool {
	switch confidence {
	case "", ConfidenceExact, ConfidenceStrong, ConfidenceGeneric, ConfidenceContextual, ConfidenceWeak:
		return true
	default:
		return false
	}
}

func isURL(raw string) bool {
	parsed, err := url.ParseRequestURI(raw)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}
