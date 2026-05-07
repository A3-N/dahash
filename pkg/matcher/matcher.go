package matcher

import (
	"regexp"
	"sort"
	"strings"

	"dahash/pkg/schema"
)

// Result is one hash type that matched an input string.
type Result struct {
	HashType schema.HashType
	Matchers []schema.Matcher
	Score    int
}

// Engine matches input strings against a schema catalog.
type Engine struct {
	catalog schema.Catalog
	regexps map[string]*regexp.Regexp
}

// New builds a matcher engine from a validated catalog.
func New(catalog schema.Catalog) (*Engine, error) {
	catalog.Normalize()
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	engine := &Engine{
		catalog: catalog,
		regexps: make(map[string]*regexp.Regexp),
	}
	for _, hashType := range catalog.HashTypes {
		for _, matcher := range hashType.Matchers {
			if matcher.Kind != schema.MatcherRegex {
				continue
			}
			pattern := matcher.Pattern
			if matcher.CaseInsensitive && !strings.HasPrefix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			engine.regexps[matcher.ID] = compiled
		}
	}
	return engine, nil
}

// Identify returns all regex-backed matches for input, sorted by score.
func (e *Engine) Identify(input string) []Result {
	input = strings.TrimSpace(input)
	results := make([]Result, 0)
	for _, hashType := range e.catalog.HashTypes {
		matched := make([]schema.Matcher, 0, len(hashType.Matchers))
		score := hashType.Priority
		for _, matcher := range hashType.Matchers {
			if matcher.Kind != schema.MatcherRegex {
				continue
			}
			compiled := e.regexps[matcher.ID]
			if compiled == nil || !compiled.MatchString(input) {
				continue
			}
			matched = append(matched, matcher)
			score += matcher.Weight + confidenceScore(matcher.Confidence)
		}
		if len(matched) == 0 {
			continue
		}
		results = append(results, Result{HashType: hashType, Matchers: matched, Score: score})
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].HashType.Priority != results[j].HashType.Priority {
			return results[i].HashType.Priority > results[j].HashType.Priority
		}
		return results[i].HashType.Name < results[j].HashType.Name
	})
	return results
}

func confidenceScore(confidence schema.ConfidenceClass) int {
	switch confidence {
	case schema.ConfidenceExact:
		return 50
	case schema.ConfidenceStrong:
		return 35
	case schema.ConfidenceContextual:
		return 20
	case schema.ConfidenceGeneric:
		return 10
	case schema.ConfidenceWeak:
		return 0
	default:
		return 5
	}
}
