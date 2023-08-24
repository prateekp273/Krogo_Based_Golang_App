package main

import (
	"net/http"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		// Validate the token using JWKS
		// If valid, proceed, else return an error
		next.ServeHTTP(w, r)
	})
}
