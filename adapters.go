package authandler

import (
	"net/http"

	"github.com/dadamssolutions/adaptd"
)

// RedirectIfErrorOnContext checks for an error on the Request's context.
// If the error is not nil, the redirect handler is called.
func RedirectIfErrorOnContext(redirectHandler http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ErrorFromContext(r.Context()) != nil {
				redirectHandler.ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// RedirectOnError redirects based on whether it kind find an error in the Request's context.
func RedirectOnError(f func(http.ResponseWriter, *http.Request) error, fh http.Handler, logOnError string) adaptd.Adapter {
	g := func(w http.ResponseWriter, r *http.Request) bool {
		err := f(w, r)
		if err != nil {
			*r = *r.WithContext(NewErrorContext(r.Context(), err))
			return false
		}
		return true
	}

	return adaptd.OnCheck(g, fh, logOnError)
}

// PostAndOtherOnError calls postHandler and then checks the error on the Request's context.
// If there is an error, the handler passed to the adapter is called.
//
// This is useful for a POST request that tries to log a user in and calls a GET handler on error.
// The GET handler can then look at the error on the Request's context.
func PostAndOtherOnError(postHandler http.Handler, redirectOnSuccess string) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				postHandler.ServeHTTP(w, r)
				if loc := w.Header().Get("Location"); loc != "" {
					return
				}
				err := ErrorFromContext(r.Context())
				if err == nil {
					http.Redirect(w, r, redirectOnSuccess, http.StatusAccepted)
					return
				}
			}
			h.ServeHTTP(w, r)
		})
	}
}

func adaptAndAbsorbError(h http.Handler, adapters ...adaptd.Adapter) http.Handler {
	// Attach adapters in reverse order because that is what should be implied by the ordering of the caller.
	// They way the middleware will work is the first adapter applied will be the last one to get called.
	// However, if there is an error on the context, we call h immediately.
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](func(f http.HandlerFunc) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f(w, r)
				if ErrorFromContext(r.Context()) != nil {
					return
				}
			})
		}(h.ServeHTTP))
	}
	return h
}
