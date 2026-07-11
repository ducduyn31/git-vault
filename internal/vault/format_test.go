package vault

import "testing"

func TestFormatForPath(t *testing.T) {
	cases := []struct {
		path string
		want Format
	}{
		{"secret.yaml", FormatYAML},
		{"secret.yml", FormatYAML},
		{"config/secret.json", FormatJSON},
		{".env", FormatDotenv},
		{".env.production", FormatDotenv},
		{"config/.env.local", FormatDotenv},
		{"app.env", FormatDotenv},
		{"key.pem", FormatBinary},
		{"noextension", FormatBinary},
		{"backup.env.old/config.yaml", FormatYAML},
	}

	for _, c := range cases {
		if got := FormatForPath(c.path); got != c.want {
			t.Errorf("FormatForPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestStoreForFormat_ReturnsNonNilForEveryFormat(t *testing.T) {
	for _, f := range []Format{FormatBinary, FormatDotenv, FormatJSON, FormatYAML} {
		if storeForFormat(f) == nil {
			t.Errorf("storeForFormat(%v) = nil", f)
		}
	}
}
