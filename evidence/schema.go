package evidence

import _ "embed"

// RecordSchema is the canonical Evidence Record JSON Schema.
//
//go:embed record.schema.json
var RecordSchema []byte

// LoadSchema returns a copy of the embedded schema.
func LoadSchema() []byte {
	return append([]byte(nil), RecordSchema...)
}
