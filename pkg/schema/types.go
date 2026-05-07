package schema

// CurrentSchemaVersion is the schema version written by new catalogs.
const CurrentSchemaVersion = "dahash.schema/v1"

// Catalog is a complete set of hash type definitions plus source metadata.
type Catalog struct {
	SchemaVersion string            `json:"schema_version"`
	Sources       []Source          `json:"sources,omitempty"`
	HashTypes     []HashType        `json:"hash_types"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// HashType describes one crackable or identifiable hash format.
type HashType struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Family       string        `json:"family,omitempty"`
	Description  string        `json:"description,omitempty"`
	Status       Status        `json:"status,omitempty"`
	Aliases      []string      `json:"aliases,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
	Priority     int           `json:"priority,omitempty"`
	Matchers     []Matcher     `json:"matchers,omitempty"`
	Tools        ToolRefs      `json:"tools,omitempty"`
	Examples     []Example     `json:"examples,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	Sources      []SourceRef   `json:"sources,omitempty"`
	Relations    []Relation    `json:"relations,omitempty"`
}

// Status captures lifecycle state for a hash type or external tool reference.
type Status string

const (
	StatusActive     Status = "active"
	StatusLegacy     Status = "legacy"
	StatusDeprecated Status = "deprecated"
	StatusSuperseded Status = "superseded"
	StatusUnknown    Status = "unknown"
)

// Matcher describes one way a hash type can be detected.
type Matcher struct {
	ID              string           `json:"id,omitempty"`
	Kind            MatcherKind      `json:"kind"`
	Scope           MatchScope       `json:"scope,omitempty"`
	Pattern         string           `json:"pattern,omitempty"`
	CaseInsensitive bool             `json:"case_insensitive,omitempty"`
	Confidence      ConfidenceClass  `json:"confidence,omitempty"`
	Weight          int              `json:"weight,omitempty"`
	Characteristics []Characteristic `json:"characteristics,omitempty"`
	Notes           string           `json:"notes,omitempty"`
	Sources         []SourceRef      `json:"sources,omitempty"`
}

// MatcherKind identifies the matcher implementation needed at runtime.
type MatcherKind string

const (
	MatcherRegex     MatcherKind = "regex"
	MatcherParser    MatcherKind = "parser"
	MatcherPrefix    MatcherKind = "prefix"
	MatcherSuffix    MatcherKind = "suffix"
	MatcherContains  MatcherKind = "contains"
	MatcherLength    MatcherKind = "length"
	MatcherComposite MatcherKind = "composite"
)

// MatchScope says what portion of input a matcher expects.
type MatchScope string

const (
	ScopeInput MatchScope = "input"
	ScopeLine  MatchScope = "line"
	ScopeToken MatchScope = "token"
	ScopeField MatchScope = "field"
)

// ConfidenceClass expresses why a match is trustworthy or ambiguous.
type ConfidenceClass string

const (
	ConfidenceExact      ConfidenceClass = "exact"
	ConfidenceStrong     ConfidenceClass = "strong"
	ConfidenceGeneric    ConfidenceClass = "generic"
	ConfidenceContextual ConfidenceClass = "contextual"
	ConfidenceWeak       ConfidenceClass = "weak"
)

// Characteristic records an observable property of a hash format.
type Characteristic struct {
	Kind       CharacteristicKind `json:"kind"`
	Key        string             `json:"key,omitempty"`
	Value      string             `json:"value,omitempty"`
	Min        *int               `json:"min,omitempty"`
	Max        *int               `json:"max,omitempty"`
	Unit       string             `json:"unit,omitempty"`
	Required   bool               `json:"required,omitempty"`
	Confidence ConfidenceClass    `json:"confidence,omitempty"`
	Notes      string             `json:"notes,omitempty"`
}

// CharacteristicKind is deliberately broad so data files can preserve facts
// before dahash has a dedicated parser for them.
type CharacteristicKind string

const (
	CharacteristicLength      CharacteristicKind = "length"
	CharacteristicAlphabet    CharacteristicKind = "alphabet"
	CharacteristicPrefix      CharacteristicKind = "prefix"
	CharacteristicSuffix      CharacteristicKind = "suffix"
	CharacteristicSeparator   CharacteristicKind = "separator"
	CharacteristicFieldCount  CharacteristicKind = "field_count"
	CharacteristicField       CharacteristicKind = "field"
	CharacteristicEncoding    CharacteristicKind = "encoding"
	CharacteristicChecksum    CharacteristicKind = "checksum"
	CharacteristicExtractor   CharacteristicKind = "extractor"
	CharacteristicContextHint CharacteristicKind = "context_hint"
)

// ToolRefs links a hash type to cracking or extraction tools.
type ToolRefs struct {
	Hashcat    []HashcatRef   `json:"hashcat,omitempty"`
	John       []JohnRef      `json:"john,omitempty"`
	Extractors []ExtractorRef `json:"extractors,omitempty"`
}

// HashcatRef maps a hash type to one hashcat mode.
type HashcatRef struct {
	Mode       int         `json:"mode"`
	Name       string      `json:"name,omitempty"`
	Status     Status      `json:"status,omitempty"`
	Deprecated bool        `json:"deprecated,omitempty"`
	Sources    []SourceRef `json:"sources,omitempty"`
	Notes      string      `json:"notes,omitempty"`
}

// JohnRef maps a hash type to one John the Ripper format label.
type JohnRef struct {
	Format     string      `json:"format"`
	Name       string      `json:"name,omitempty"`
	Status     Status      `json:"status,omitempty"`
	Deprecated bool        `json:"deprecated,omitempty"`
	Sources    []SourceRef `json:"sources,omitempty"`
	Notes      string      `json:"notes,omitempty"`
}

// ExtractorRef identifies a helper that can produce the crackable hash string.
type ExtractorRef struct {
	Name       string      `json:"name"`
	Command    string      `json:"command,omitempty"`
	OutputKind string      `json:"output_kind,omitempty"`
	Sources    []SourceRef `json:"sources,omitempty"`
	Notes      string      `json:"notes,omitempty"`
}

// Example is a sample value, URL, file reference, or extractor note.
type Example struct {
	Kind      ExampleKind `json:"kind"`
	Value     string      `json:"value"`
	Plaintext string      `json:"plaintext,omitempty"`
	Verified  bool        `json:"verified,omitempty"`
	Sources   []SourceRef `json:"sources,omitempty"`
	Notes     string      `json:"notes,omitempty"`
}

// ExampleKind describes how to interpret Example.Value.
type ExampleKind string

const (
	ExampleInline    ExampleKind = "inline"
	ExampleURL       ExampleKind = "url"
	ExampleFile      ExampleKind = "file"
	ExampleExtractor ExampleKind = "extractor"
)

// Observation stores facts learned from an observed hash or external source.
type Observation struct {
	ID              string           `json:"id,omitempty"`
	Value           string           `json:"value,omitempty"`
	Context         string           `json:"context,omitempty"`
	Characteristics []Characteristic `json:"characteristics,omitempty"`
	Sources         []SourceRef      `json:"sources,omitempty"`
	Notes           string           `json:"notes,omitempty"`
}

// Source is a source database, project, document, tool, or manual research set.
type Source struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      SourceKind `json:"kind,omitempty"`
	URL       string     `json:"url,omitempty"`
	Version   string     `json:"version,omitempty"`
	License   string     `json:"license,omitempty"`
	Retrieved string     `json:"retrieved,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}

// SourceKind classifies source records.
type SourceKind string

const (
	SourceProject       SourceKind = "project"
	SourceDocumentation SourceKind = "documentation"
	SourceTool          SourceKind = "tool"
	SourceResearch      SourceKind = "research"
	SourceGenerated     SourceKind = "generated"
)

// SourceRef points at a Source and optional source-local identifier.
type SourceRef struct {
	ID       string `json:"id"`
	Ref      string `json:"ref,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// Relation records semantic links between hash type definitions.
type Relation struct {
	Kind   RelationKind `json:"kind"`
	Target string       `json:"target"`
	Notes  string       `json:"notes,omitempty"`
}

// RelationKind describes how one hash type relates to another.
type RelationKind string

const (
	RelationAliasOf       RelationKind = "alias_of"
	RelationEquivalentTo  RelationKind = "equivalent_to"
	RelationSupersedes    RelationKind = "supersedes"
	RelationSupersededBy  RelationKind = "superseded_by"
	RelationConflictsWith RelationKind = "conflicts_with"
	RelationVariantOf     RelationKind = "variant_of"
)
