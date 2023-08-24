package main

import (
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
)

var jwksSet jwk.Set

func init() {
	var err error
	jwksURL := "https://your-merch-hub.com/.well-known/jwks.json"
	jwksSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		log.Fatalf("Failed to fetch JWKS: %s", err)
	}
}

func checkPermission(jwtToken string, requestData map[string]interface{}) bool {
	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://merch-hub.com/check-permission", nil)
	req.Header.Set("Authorization", jwtToken)
	// Add requestData to the request body
	// Send the request and check the response
	// Return true if permission is granted, false otherwise
	return true
}

func handleRestrictedAPI(w http.ResponseWriter, r *http.Request) {
	// Extract data from the request
	data := map[string]interface{}{
		"FT":        r.FormValue("FT"),
		"Geography": r.FormValue("Geography"),
		"Modality":  r.FormValue("Modality"),
	}
	// Check permission
	if !checkPermission(r.Header.Get("Authorization"), data) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Handle the request
}

func main() {
	http.Handle("/restricted-endpoint", JWTMiddleware(http.HandlerFunc(handleRestrictedAPI)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
