package vault

import (
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
)

// Format identifies which sops store git-vault uses for a document.
type Format int

const (
	// FormatBinary treats the whole file as one opaque ciphertext blob.
	// It is the fallback for any extension not otherwise recognized.
	FormatBinary Format = iota
	// FormatDotenv preserves KEY=value structure; only values are
	// encrypted.
	FormatDotenv
	// FormatJSON preserves object structure; only leaf values are
	// encrypted.
	FormatJSON
	// FormatYAML preserves document structure; only leaf values are
	// encrypted.
	FormatYAML
)

// FormatForPath returns the Format git-vault uses for path, based on its
// file extension: .yaml/.yml and .json get sops's structure-preserving
// stores; ".env" and any ".env.<suffix>" file (e.g. ".env.production")
// get the dotenv store; anything else falls back to the binary
// (whole-file) store.
func FormatForPath(path string) Format {
	switch {
	case strings.HasSuffix(path, ".env") || strings.Contains(path, ".env."):
		return FormatDotenv
	case strings.HasSuffix(path, ".json"):
		return FormatJSON
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		return FormatYAML
	default:
		return FormatBinary
	}
}

// storeForFormat returns the sops Store implementation for format. JSON
// gets an explicit 2-space indent so committed files diff cleanly
// (sops's JSON store defaults to a bare, near-compact reindent otherwise).
func storeForFormat(format Format) sops.Store {
	switch format {
	case FormatDotenv:
		return dotenv.NewStore(&config.DotenvStoreConfig{})
	case FormatJSON:
		return json.NewStore(&config.JSONStoreConfig{Indent: 2})
	case FormatYAML:
		return yaml.NewStore(&config.YAMLStoreConfig{})
	default:
		return json.NewBinaryStore(&config.JSONBinaryStoreConfig{})
	}
}
