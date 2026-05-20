package docs

import _ "embed"

// SwaggerSpec is the embedded OpenAPI 3.0 specification served at /api/v1/docs.
//
//go:embed swagger.json
var SwaggerSpec []byte
