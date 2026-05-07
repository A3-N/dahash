package schema

// CurrentHashTypeDocumentVersion is the schema version written for one-file
// hash type documents under data/hash-types.
const CurrentHashTypeDocumentVersion = "dahash.hash_type/v1"

// CurrentSourceDocumentVersion is the schema version written for source
// metadata documents.
const CurrentSourceDocumentVersion = "dahash.sources/v1"

// HashTypeDocument stores one canonical hash type in a standalone JSON file.
type HashTypeDocument struct {
	SchemaVersion string `json:"schema_version"`
	HashType
}

// Normalize applies document defaults and hash type normalization.
func (d *HashTypeDocument) Normalize() {
	if d.SchemaVersion == "" {
		d.SchemaVersion = CurrentHashTypeDocumentVersion
	}
	d.HashType.Normalize()
}

// SourceDocument stores shared source metadata referenced by hash type files.
type SourceDocument struct {
	SchemaVersion string   `json:"schema_version"`
	Sources       []Source `json:"sources"`
}

// Normalize applies document defaults and source normalization.
func (d *SourceDocument) Normalize() {
	if d.SchemaVersion == "" {
		d.SchemaVersion = CurrentSourceDocumentVersion
	}
	d.Sources = normalizeSources(d.Sources)
}
