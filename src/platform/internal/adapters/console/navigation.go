package console

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// Fetch callers explicitly opt into JSON: an opaque cross-origin redirect
// cannot be used to navigate a top-level browser with a JSON/CSRF POST.
func authorizationResponse(w http.ResponseWriter, r *http.Request, location string) {
	w.Header().Set("Vary", "Accept")
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"authorizationUrl": location})
		return
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

var errorPage = template.Must(template.New("auth-error").Parse(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Acceso a HukID</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{margin:0;padding:24px}main{max-width:40rem;margin:10vh auto}h1{line-height:1.2}a{display:inline-flex;align-items:center;min-height:48px;padding:0 16px}a:focus-visible{outline:3px solid currentColor;outline-offset:4px}</style></head>
<body><main><h1>No se pudo completar el acceso</h1><p>Vuelve a la consola para comprobar tu sesión o iniciar sesión de nuevo. Si el problema persiste, contacta con tu administrador.</p><p><a href="/">Volver a HukID</a></p></main></body></html>`))

// Browser callback failures retain their HTTP status and contain no request data.
// API/contract callers continue receiving Problem Details.
type browserProblemWriter struct{ http.ResponseWriter }

func (w browserProblemWriter) WriteHeader(status int) {
	if status >= 400 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w browserProblemWriter) Write(data []byte) (int, error) {
	if w.Header().Get("Content-Type") == "text/html; charset=utf-8" {
		return len(data), errorPage.Execute(w.ResponseWriter, nil)
	}
	return w.ResponseWriter.Write(data)
}
