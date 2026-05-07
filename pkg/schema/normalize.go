package schema

import (
	"sort"
	"strings"
)

// Normalize applies deterministic defaults and removes duplicate simple values.
func (c *Catalog) Normalize() {
	c.SchemaVersion = strings.TrimSpace(c.SchemaVersion)
	if c.SchemaVersion == "" {
		c.SchemaVersion = CurrentSchemaVersion
	}
	c.Sources = normalizeSources(c.Sources)
	for i := range c.HashTypes {
		c.HashTypes[i].Normalize()
	}
	sort.SliceStable(c.HashTypes, func(i, j int) bool {
		return c.HashTypes[i].ID < c.HashTypes[j].ID
	})
}

// Normalize applies deterministic defaults to a hash type.
func (h *HashType) Normalize() {
	h.ID = strings.TrimSpace(h.ID)
	h.Name = strings.TrimSpace(h.Name)
	h.Family = strings.TrimSpace(h.Family)
	h.Description = strings.TrimSpace(h.Description)
	if h.Status == "" {
		h.Status = StatusActive
	}
	h.Aliases = cleanUniqueStrings(h.Aliases)
	h.Tags = cleanUniqueStrings(h.Tags)
	h.Sources = normalizeSourceRefs(h.Sources)
	h.Relations = normalizeRelations(h.Relations)
	for i := range h.Matchers {
		h.Matchers[i].Normalize()
	}
	h.Matchers = dedupeMatchers(h.Matchers)
	h.Tools.Normalize()
	for i := range h.Examples {
		h.Examples[i].Normalize()
	}
	h.Examples = dedupeExamples(h.Examples)
	for i := range h.Observations {
		h.Observations[i].Normalize()
	}
	h.Observations = dedupeObservations(h.Observations)
}

// Normalize applies deterministic defaults to a matcher.
func (m *Matcher) Normalize() {
	m.ID = strings.TrimSpace(m.ID)
	m.Pattern = strings.TrimSpace(m.Pattern)
	m.Notes = strings.TrimSpace(m.Notes)
	if m.Scope == "" {
		m.Scope = ScopeInput
	}
	if m.Confidence == "" {
		m.Confidence = ConfidenceGeneric
	}
	m.Sources = normalizeSourceRefs(m.Sources)
	for i := range m.Characteristics {
		m.Characteristics[i].Normalize()
	}
}

// Normalize applies deterministic defaults to tool references.
func (t *ToolRefs) Normalize() {
	for i := range t.Hashcat {
		t.Hashcat[i].Name = strings.TrimSpace(t.Hashcat[i].Name)
		t.Hashcat[i].Notes = strings.TrimSpace(t.Hashcat[i].Notes)
		if t.Hashcat[i].Status == "" {
			t.Hashcat[i].Status = StatusActive
		}
		t.Hashcat[i].Sources = normalizeSourceRefs(t.Hashcat[i].Sources)
	}
	for i := range t.John {
		t.John[i].Format = strings.TrimSpace(t.John[i].Format)
		t.John[i].Name = strings.TrimSpace(t.John[i].Name)
		t.John[i].Notes = strings.TrimSpace(t.John[i].Notes)
		if t.John[i].Status == "" {
			t.John[i].Status = StatusActive
		}
		t.John[i].Sources = normalizeSourceRefs(t.John[i].Sources)
	}
	for i := range t.Extractors {
		t.Extractors[i].Name = strings.TrimSpace(t.Extractors[i].Name)
		t.Extractors[i].Command = strings.TrimSpace(t.Extractors[i].Command)
		t.Extractors[i].OutputKind = strings.TrimSpace(t.Extractors[i].OutputKind)
		t.Extractors[i].Notes = strings.TrimSpace(t.Extractors[i].Notes)
		t.Extractors[i].Sources = normalizeSourceRefs(t.Extractors[i].Sources)
	}
	t.Hashcat = dedupeHashcatRefs(t.Hashcat)
	t.John = dedupeJohnRefs(t.John)
	t.Extractors = dedupeExtractorRefs(t.Extractors)
}

// Normalize applies deterministic defaults to an example.
func (e *Example) Normalize() {
	e.Value = strings.TrimSpace(e.Value)
	e.Plaintext = strings.TrimSpace(e.Plaintext)
	e.Notes = strings.TrimSpace(e.Notes)
	if e.Kind == "" {
		e.Kind = ExampleInline
	}
	e.Sources = normalizeSourceRefs(e.Sources)
}

// Normalize applies deterministic defaults to an observation.
func (o *Observation) Normalize() {
	o.ID = strings.TrimSpace(o.ID)
	o.Value = strings.TrimSpace(o.Value)
	o.Context = strings.TrimSpace(o.Context)
	o.Notes = strings.TrimSpace(o.Notes)
	o.Sources = normalizeSourceRefs(o.Sources)
	for i := range o.Characteristics {
		o.Characteristics[i].Normalize()
	}
}

// Normalize applies deterministic defaults to a characteristic.
func (c *Characteristic) Normalize() {
	c.Key = strings.TrimSpace(c.Key)
	c.Value = strings.TrimSpace(c.Value)
	c.Unit = strings.TrimSpace(c.Unit)
	c.Notes = strings.TrimSpace(c.Notes)
	if c.Confidence == "" {
		c.Confidence = ConfidenceGeneric
	}
}

func normalizeSources(sources []Source) []Source {
	for i := range sources {
		sources[i].ID = strings.TrimSpace(sources[i].ID)
		sources[i].Name = strings.TrimSpace(sources[i].Name)
		sources[i].URL = strings.TrimSpace(sources[i].URL)
		sources[i].Version = strings.TrimSpace(sources[i].Version)
		sources[i].License = strings.TrimSpace(sources[i].License)
		sources[i].Retrieved = strings.TrimSpace(sources[i].Retrieved)
		sources[i].Notes = strings.TrimSpace(sources[i].Notes)
	}
	sort.SliceStable(sources, func(i, j int) bool {
		return sources[i].ID < sources[j].ID
	})
	return dedupeSources(sources)
}

func normalizeSourceRefs(refs []SourceRef) []SourceRef {
	for i := range refs {
		refs[i].ID = strings.TrimSpace(refs[i].ID)
		refs[i].Ref = strings.TrimSpace(refs[i].Ref)
		refs[i].Revision = strings.TrimSpace(refs[i].Revision)
	}
	return dedupeSourceRefs(refs)
}

func normalizeRelations(relations []Relation) []Relation {
	for i := range relations {
		relations[i].Target = strings.TrimSpace(relations[i].Target)
		relations[i].Notes = strings.TrimSpace(relations[i].Notes)
	}
	return dedupeRelations(relations)
}

func cleanUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
