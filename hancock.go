// Copyright 2014 Justin Wilson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Hancock signs and validates URL/Requests.
package hancock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Error is used by Validate to return an error with
// a matching HTTP status code.
type Error struct {
	s      string
	Status int
}

// Error returns the error message.
func (e Error) Error() string {
	return e.s
}

func isValidTS(ts string, expireSeconds int) (string, bool) {
	if i, err := strconv.ParseInt(ts, 10, 64); err == nil {
		now := time.Now().UTC().Unix()
		dur := now - i
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
			return nil, newError(http.StatusNotAcceptable, "%s timestamp %s", s, ts)
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
		return nil, newError(http.StatusUnauthorized, "signature mismatch `%s` != `%s`", encHash, data)
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

func newError(s int, f string, p ...interface{}) *Error {
	return &Error{
		s:      fmt.Sprintf(f, p...),
		Status: s,
	}
}
