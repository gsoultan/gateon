package middleware

import (
	"fmt"
	"net/http"
)

func (f *Factory) createInflightReq(cfg map[string]string) (Middleware, error) {
	amount, _ := strconvParseInt(cfg["amount"], 0)
	if amount <= 0 {
		return nil, fmt.Errorf("inflightreq requires amount > 0")
	}
	perIP := parseBoolStrict(cfg["per_ip"], true)
	keyFunc := PerIP
	if !perIP {
		keyFunc = func(r *http.Request) string { return r.Host }
	}
	return MaxConnectionsPerIP(amount, keyFunc), nil
}
