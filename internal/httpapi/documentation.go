package httpapi

import (
	"fmt"
	"io/fs"
	"net/http"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/docs"
)

func newDocumentationHandler() http.Handler {
	assets, err := fs.Sub(docs.SwaggerUI, "swagger-ui")
	if err != nil {
		panic(fmt.Sprintf("httpapi: Swagger UI assets unavailable: %v", err))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if _, err := w.Write(docs.GatewayOpenAPI); err != nil {
			return
		}
	})
	mux.HandleFunc("GET /swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
	})
	mux.Handle("GET /swagger/", http.StripPrefix("/swagger/", http.FileServer(http.FS(assets))))
	return mux
}
