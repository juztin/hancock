// Copyright 2014 Justin Wilson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Hancock signs and validates URL/Requests.
package hancock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type RequestInfo struct {
	APIKey     string      `json:"apiKey"`
	Host       string      `json:"host"`
	Proto      string      `json:"proto"`
	RemoteAddr string      `json:"remoteAddr"`
	RequestURI string      `json:"requestURI"`
	Header     interface{} `json:"header"`
	//Header     string      `json:"header"`
}

// Error is used by Validate to return an error with
// a matching HTTP status code.
type Error struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Request RequestInfo `json:"request"`
}

type LogFunc func(...interface{})

// KeyFunc returns the matching private key, and expiration duration,
// for the given public key
type KeyFunc func(key string) (pKey string, expires int)

type signedHandler struct {
	handler http.Handler
	key     KeyFunc
	Log     LogFunc
}

// Error returns the error message.
func (e Error) Error() string {
	return e.Message
}

func isValidTS(ts string, expireSeconds int) (string, bool) {
	if t, err := strconv.ParseInt(ts, 10, 64); err == nil {
		now := time.Now().UTC().Unix()
		dur := now - t
		if dur < 0 {
			dur = dur * -1
		}
		return "expired", dur <= int64(expireSeconds)
	}
	return "invalid", false
}

// Validate checks that the given request is valid for both the pKey and expireSeconds.
//
// The url.Values returned are that of the request minus
// the signing parameters, "apikey", "ts", "data".
// If the validation fails an error is also returned with both the message
// and an HTTP status code matching the error.
//
// When `expireSeconds` is -1 the time check is skipped
// When `expireSeconds` is -2 the security check is skipped altogether (everything is valid)
// ** 0 was not used as it's the default value for ints, and could allow attacks
//    when `expireSeconds` is not set properly
func Validate(r *http.Request, pKey string, expireSeconds int) (url.Values, *Error) {
	v := r.URL.Query()
	switch expireSeconds {
	default: // Validate expire seconds is in range
		ts := v.Get("ts")
		if s, ok := isValidTS(ts, expireSeconds); !ok {
			return nil, newError(http.StatusNotAcceptable, r, "%s timestamp %s", s, ts)
		}
	case -1: // Ignore expire time
		// pass
	case -2: // Disable security altogether
		v.Del("data")
		v.Del("apikey")
		v.Del("ts")
		return v, nil
	}

	// Generate `METHOD:QUERY_STRING` string for hashing (removing `data` param)
	data := v.Get("data")
	v.Del("data")
	sig := fmt.Sprintf("%s:%s", r.Method, v.Encode())

	// Validate hash
	hash := hmac.New(sha256.New, []byte(pKey))
	hash.Write([]byte(sig))
	encHash := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	if encHash != data {
		return nil, newError(http.StatusUnauthorized, r, "signature mismatch `%s` != `%s`", encHash, data)
	}

	// Remove remaining signature params
	v.Del("apikey")
	v.Del("ts")
	return v, nil
}

// SignQS returns a signed query-string from the given "qs".
func SignQS(method, key, pKey string, values url.Values) string {
	v := make(url.Values)
	if values != nil {
		for k, o := range values {
			v[k] = o
		}
	}

	v.Add("apikey", key)
	v.Add("ts", fmt.Sprintf("%d", time.Now().UTC().Unix()))

	// Generate signature
	enc := v.Encode() // Encode sorts by keys (I think this was added with 1.2'ish?)
	sig := fmt.Sprintf("%s:%s", method, enc)
	hash := hmac.New(sha256.New, []byte(pKey))
	hash.Write([]byte(sig))
	encHash := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	v.Add("data", encHash)
	return v.Encode()
}

// Sign returns a signed URL.
func Sign(method, key, pKey, urlStr string, qs url.Values) string {
	return fmt.Sprintf("%s?%s", urlStr, SignQS(method, key, pKey, qs))
}

func (h *signedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("apikey")
	pKey, expires := h.key(key)
	if pKey == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if _, err := Validate(r, pKey, expires); err != nil {
		w.WriteHeader(err.Status)
		h.Log(err)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func SignedHandler(h http.Handler, keyFn KeyFunc, logFn LogFunc) http.Handler {
	return &signedHandler{h, keyFn, logFn}
}

func newError(status int, r *http.Request, fmtStr string, params ...interface{}) *Error {
	header, _ := json.Marshal(r.Header)
	return &Error{
		Status:  status,
		Message: fmt.Sprintf(fmtStr, params...),
		Request: RequestInfo{
			r.URL.Query().Get("apikey"),
			r.Host,
			r.Proto,
			r.RemoteAddr,
			r.RequestURI,
			string(header),
		},
	}
}
