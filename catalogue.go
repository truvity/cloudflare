package cloudflare

import "embed"

// R2BrokerCatalogueFS embeds the R2 credential broker's audit catalogue
// directory: catalogue/r2broker.yaml and the JSON Schemas its two actions'
// data_schema fields reference. It lives here, at the module root, rather
// than beside internal/audit (which registers and validates it) because
// a `//go:embed` directive cannot reach outside the directory containing
// its source file — it can only descend into subdirectories of it — and
// catalogue/ and internal/audit/ are siblings.
//
//go:embed catalogue
var R2BrokerCatalogueFS embed.FS
