package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// EnsureCorrelationID reads X-Bastion-Correlation-Id from the request.
// If absent, generates a new one and sets it on the request context.
func EnsureCorrelationID(r *http.Request) string {
	cid := r.Header.Get("X-Bastion-Correlation-Id")
	if cid != "" {
		return cid
	}
	b := make([]byte, 16)
	rand.Read(b)
	cid = hex.EncodeToString(b)
	r.Header.Set("X-Bastion-Correlation-Id", cid)
	return cid
}

// PropagateCorrelationID sets the X-Bastion-Correlation-Id header on an outbound request.
func PropagateCorrelationID(req *http.Request, correlationID string) {
	req.Header.Set("X-Bastion-Correlation-Id", correlationID)
}
