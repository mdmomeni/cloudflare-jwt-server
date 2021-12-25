package main

import (
	"crypto/rsa"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	alg         = "RS256"
	privKeyPath = "private.pem"
	pubKeyPath  = "public.pem"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
}

// Define some custom types were going to use within our tokens
type UserInfo struct {
	Username string
}

func createToken(username string) (string, error) {

	token := jwt.New(jwt.GetSigningMethod(alg))
	token.Claims = jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
	}

	return token.SignedString(signKey)
}

// This endpoint recieve a cookie from user (client)
// and verifies that the cookie is signed and unexpired
// it'll return the username itself as plain text if the cookie is ok
func verify(w http.ResponseWriter, r *http.Request) {
	// jwtCookie := r.Header.Get("Cookie")
	// w.Write([]byte())
}

// This endpoint creates a JWT and sends it back to the user as a cookie.
// The body of the response will be the RSA public key in plain text.
func authHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	jwtCookie, err := createToken(username)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	tomorrowDate := time.Now().AddDate(0, 0, 1)
	cookieValue := "token=" + jwtCookie + "; Expires=" + tomorrowDate.String()
	r.Header.Set("Set-Cookie", cookieValue)
	w.Write(verifyKey.N.Bytes())
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Get requests
	r.Get("/verify", verify)
	r.Get("/auth/{username}", authHandler)

	http.ListenAndServe(":8080", r)
}
