package staticsite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"path"
	"regexp"
	"strings"
)

// textKind is the escaping context of a text type that takes placeholders.
type textKind int

const (
	kindNone textKind = iota
	kindHTML
	kindJS
	kindCSS
	kindJSON
)

func kindOf(name string) textKind {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm":
		return kindHTML
	case ".js", ".mjs":
		return kindJS
	case ".css":
		return kindCSS
	case ".json", ".webmanifest":
		return kindJSON
	}
	return kindNone
}

// token is {{ name }}; spaces inside the braces are optional.
var token = regexp.MustCompile(`\{\{\s*([A-Za-z][A-Za-z0-9_-]{0,63})\s*\}\}`)

// substitute replaces the allowlisted tokens in data. A token that is not in
// values is left exactly as written. The value is escaped for the context
// of the file; in JS and JSON the token must sit inside a string literal.
func substitute(kind textKind, data []byte, values map[string]string) []byte {
	if kind == kindNone || len(values) == 0 || !bytes.Contains(data, []byte("{{")) {
		return data
	}
	return token.ReplaceAllFunc(data, func(m []byte) []byte {
		name := token.FindSubmatch(m)[1]
		v, ok := values[string(name)]
		if !ok {
			return m
		}
		return []byte(escape(kind, v))
	})
}

// checkTokens enforces strict mode: every token in a text file must name a
// placeholder that has a value. It reports names only, never values.
func checkTokens(file string, kind textKind, data []byte, cfg *Config) error {
	if !cfg.PlaceholderStrict || kind == kindNone || !bytes.Contains(data, []byte("{{")) {
		return nil
	}
	declared := map[string]bool{}
	for _, k := range cfg.PlaceholderKeys {
		declared[k] = true
	}
	var errs []error
	seen := map[string]bool{}
	for _, m := range token.FindAllSubmatch(data, -1) {
		name := string(m[1])
		if _, ok := cfg.Placeholders[name]; ok || seen[name] {
			continue
		}
		seen[name] = true
		if declared[name] {
			errs = append(errs, fmt.Errorf("%s: placeholder %q has no value", file, name))
		} else {
			errs = append(errs, fmt.Errorf("%s: unknown placeholder %q", file, name))
		}
	}
	return errors.Join(errs...)
}

func escape(kind textKind, v string) string {
	switch kind {
	case kindHTML:
		return html.EscapeString(v)
	case kindJS:
		return jsEscape(v)
	case kindCSS:
		return cssEscape(v)
	case kindJSON:
		b, _ := json.Marshal(v)
		return string(b[1 : len(b)-1])
	}
	return v
}

func jsEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '\\', r == '\'', r == '"', r == '`', r == '<', r == '>', r == '&', r == '$', r == '=':
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x20, r == 0x7f, r == 0x2028, r == 0x2029:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cssEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\%x `, r)
		}
	}
	return b.String()
}
