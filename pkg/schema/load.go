package schema

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadSourceDocument reads source metadata from one JSON file.
func LoadSourceDocument(path string) (SourceDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SourceDocument{}, fmt.Errorf("read source document %s: %w", path, err)
	}
	var doc SourceDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return SourceDocument{}, fmt.Errorf("parse source document %s: %w", path, err)
	}
	doc.Normalize()
	return doc, nil
}

// LoadHashTypeDocument reads one hash type JSON file.
func LoadHashTypeDocument(path string) (HashTypeDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return HashTypeDocument{}, fmt.Errorf("read hash type document %s: %w", path, err)
	}
	var doc HashTypeDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return HashTypeDocument{}, fmt.Errorf("parse hash type document %s: %w", path, err)
	}
	doc.Normalize()
	return doc, nil
}

// LoadCatalogFromDirectory loads a source document plus all hash type JSON
// files under hashTypesDir. The directory is walked recursively so definitions
// can be grouped by family later without changing loader behavior.
func LoadCatalogFromDirectory(sourcesPath, hashTypesDir string) (Catalog, error) {
	sourceDoc, err := LoadSourceDocument(sourcesPath)
	if err != nil {
		return Catalog{}, err
	}
	catalog := Catalog{
		SchemaVersion: CurrentSchemaVersion,
		Sources:       sourceDoc.Sources,
	}
	err = filepath.WalkDir(hashTypesDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		doc, err := LoadHashTypeDocument(path)
		if err != nil {
			return err
		}
		catalog.HashTypes = append(catalog.HashTypes, doc.HashType)
		return nil
	})
	if err != nil {
		return Catalog{}, fmt.Errorf("load hash type directory %s: %w", hashTypesDir, err)
	}
	catalog.Normalize()
	return catalog, catalog.Validate()
}
