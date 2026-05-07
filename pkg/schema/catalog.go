package schema

import (
	"sort"
	"strings"
)

func dedupeMatchers(matchers []Matcher) []Matcher {
	seen := make(map[string]struct{}, len(matchers))
	out := make([]Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		matcher.Normalize()
		key := matcher.ID
		if key == "" {
			key = string(matcher.Kind) + "\x00" + matcher.Pattern
		}
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, matcher)
	}
	return out
}

func dedupeHashcatRefs(refs []HashcatRef) []HashcatRef {
	seen := make(map[int]struct{}, len(refs))
	out := make([]HashcatRef, 0, len(refs))
	for _, ref := range refs {
		if _, exists := seen[ref.Mode]; exists {
			continue
		}
		seen[ref.Mode] = struct{}{}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Mode < out[j].Mode
	})
	return out
}

func dedupeJohnRefs(refs []JohnRef) []JohnRef {
	seen := make(map[string]struct{}, len(refs))
	out := make([]JohnRef, 0, len(refs))
	for _, ref := range refs {
		key := strings.ToLower(strings.TrimSpace(ref.Format))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Format < out[j].Format
	})
	return out
}

func dedupeExtractorRefs(refs []ExtractorRef) []ExtractorRef {
	seen := make(map[string]struct{}, len(refs))
	out := make([]ExtractorRef, 0, len(refs))
	for _, ref := range refs {
		key := strings.ToLower(strings.TrimSpace(ref.Name))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func dedupeExamples(examples []Example) []Example {
	seen := make(map[string]struct{}, len(examples))
	out := make([]Example, 0, len(examples))
	for _, example := range examples {
		example.Normalize()
		key := string(example.Kind) + "\x00" + example.Value
		if example.Value == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, example)
	}
	return out
}

func dedupeObservations(observations []Observation) []Observation {
	seen := make(map[string]struct{}, len(observations))
	out := make([]Observation, 0, len(observations))
	for _, observation := range observations {
		observation.Normalize()
		key := observation.ID
		if key == "" {
			key = observation.Value + "\x00" + observation.Context
		}
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, observation)
	}
	return out
}

func dedupeSources(sources []Source) []Source {
	seen := make(map[string]struct{}, len(sources))
	out := make([]Source, 0, len(sources))
	for _, source := range sources {
		if source.ID == "" {
			continue
		}
		if _, exists := seen[source.ID]; exists {
			continue
		}
		seen[source.ID] = struct{}{}
		out = append(out, source)
	}
	return out
}

func dedupeSourceRefs(refs []SourceRef) []SourceRef {
	seen := make(map[string]struct{}, len(refs))
	out := make([]SourceRef, 0, len(refs))
	for _, ref := range refs {
		if ref.ID == "" {
			continue
		}
		key := ref.ID + "\x00" + ref.Ref + "\x00" + ref.Revision
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func dedupeRelations(relations []Relation) []Relation {
	seen := make(map[string]struct{}, len(relations))
	out := make([]Relation, 0, len(relations))
	for _, relation := range relations {
		if relation.Kind == "" || relation.Target == "" {
			continue
		}
		key := string(relation.Kind) + "\x00" + relation.Target
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, relation)
	}
	return out
}
