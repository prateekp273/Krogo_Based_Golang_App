package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type JWKS struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func GetJWKS(url string) (*JWKS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	return &jwks, nil
}

func ValidateToken(jwks *JWKS, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token, jwks)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token is not valid")
	}

	return token, nil
}

func getPemCert(token *jwt.Token, jwks *JWKS) (string, error) {
	cert := ""
	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].N + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		return cert, errors.New("unable to find appropriate key")
	}

	return cert, nil
}

func callAPIWithToken(token string) (string, error) {
	url := "https://myapi.com/api"

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func RestrictedEndpoint(w http.ResponseWriter, r *http.Request) {
	// Using the provided access_token directly for testing
	tokenString := "eyJz93a...k4laUWw"

	jwks, err := GetJWKS("https://dev-tt2mwjf5w6c3kw2i.us.auth0.com/.well-known/jwks.json")
	if err != nil {
		http.Error(w, "Error fetching JWKS", http.StatusInternalServerError)
		return
	}

	_, err = ValidateToken(jwks, tokenString)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Call the API with the token after validation
	apiResponse, err := callAPIWithToken(tokenString)
	if err != nil {
		http.Error(w, "Error calling API", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Access granted! API Response: " + apiResponse))
}

func main() {
	http.HandleFunc("/restricted", RestrictedEndpoint)
	http.ListenAndServe(":8080", nil)
}
