package wrappers

import (
	"log"
	"net/http"

	"bitbucket.org/juztin/dingo"
	"bitbucket.org/juztin/dingo/rest"
	"bitbucket.org/juztin/hancock"
)

type KeyFunc func(key string) (string, error)

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

func SignedWrapper(keyFunc KeyFunc, expireSeconds int) rest.Wrapper {
	return func(handlerFunc rest.Handler) dingo.Handler {
		return rest.Wrap(WrapSigned(keyFunc, expireSeconds, handlerFunc))
	}
}
