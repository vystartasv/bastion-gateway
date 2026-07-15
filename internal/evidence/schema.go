package evidence

import rootschema "github.com/vystartasv/bastion-gateway/evidence"

// LoadSchema returns a copy of the canonical embedded JSON Schema.
func LoadSchema() []byte {
	return rootschema.LoadSchema()
}
