package wrappers

import (
	"log"
	"net/http"

	"code.minty.io/dingo"
	"code.minty.io/dingo/rest"
	"code.minty.io/hancock"
)

// KeyFunc returns a private key for the given public key.
type KeyFunc func(key string) (string, error)

// WrapSigned wraps the given handler and verifies the signature before invoking the handler.
func WrapSigned(keyFunc KeyFunc, expireSeconds int, handlerFunc rest.Handler) rest.Handler {
	return func(ctx dingo.Context) (int, interface{}) {
		key := ctx.URL.Query().Get("apikey")
		pKey, err := keyFunc(key)
		if err != nil {
			log.Printf("API key retrieval failed: `%s`; %s", key, err)
			return http.StatusUnauthorized, nil
		}

		qs, hErr := hancock.Validate(ctx.Request, pKey, expireSeconds)
		if hErr != nil {
			log.Printf("URL validation failed for query-string: `%s`; %s", ctx.URL.RawQuery, hErr)
			return hErr.Status, nil
		}

		ctx.URL.RawQuery = qs.Encode()
		ctx.RouteData["apikey"] = key
		return handlerFunc(ctx)
	}
}

// SignedWrapper returns a wrapper function preset with the keyFunc and expiration duration.
func SignedWrapper(keyFunc KeyFunc, expireSeconds int) rest.Wrapper {
	return func(handlerFunc rest.Handler) dingo.Handler {
		return rest.Wrap(WrapSigned(keyFunc, expireSeconds, handlerFunc))
	}
}
