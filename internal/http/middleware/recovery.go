package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	httpkitmiddleware "github.com/containeroo/httpkit/middleware"
	httpkitresponse "github.com/containeroo/httpkit/response"
	httpresponse "github.com/gi8lino/keycloak-warden/internal/http/response"
)

// RecoverPanics converts handler panics into logged internal server errors.
func RecoverPanics(logger *slog.Logger) httpkitmiddleware.Middleware {
	recover := httpkitmiddleware.RecoverPanics(
		func(w http.ResponseWriter, _ *http.Request, recovered any) {
			httpresponse.InternalServerError(
				logger.With("operation", "request_panic"),
				w,
				fmt.Errorf("request panic: %v", recovered),
			)
		},
		func(w http.ResponseWriter) bool {
			response, ok := w.(*httpkitresponse.RequestWriter)
			return ok && response.Status != 0
		},
	)
	return func(next http.Handler) http.Handler {
		recovered := recover(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, tracked := w.(*httpkitresponse.RequestWriter); !tracked {
				w = httpkitresponse.NewRequestWriter(w, r)
			}
			recovered.ServeHTTP(w, r)
		})
	}
}
