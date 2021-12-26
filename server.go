package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	privKeyPath = "private.pem"
	pubKeyPath  = "public.pem"
	cookieKey   = "token"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func tokenExpiration() time.Time{
	// return time.Now().AddDate(0, 0, 1)
	return time.Now().Add(time.Second * 40)
}

func setPrivateKey() {
	privKeyBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		fmt.Print(err.Error())
		log.Fatal("Error while reading the PRIVATE KEY using `ReadFile`")
	}
	priv, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(privKeyBytes, "moehmeni")
	if err != nil {
		fmt.Print(err.Error())
		log.Fatal("\nError while parsing the PRIVATE KEY using `jwt.ParseRSAPrivateKeyFromPEM`")
	}

	privateKey = priv
}

func setPublicKey() {
	publicKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Print(err.Error())
		log.Fatal("Error while reading the PUBLIC KEY using `ReadFile`")
	}

	pub, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)

	if err != nil {
		fmt.Print(err.Error())
		log.Fatal("\nError while parsing the PUBLIC KEY using `jwt.ParseRSAPrivateKeyFromPEM`")
	}

	publicKey = pub
}

func createToken(username string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: tokenExpiration().Unix(),
	})

	return token.SignedString(privateKey)
}

// Since we only use the one private key to sign the tokens,
// we also only use its public counter part to verify
// [Resource](https://github.com/dgrijalva/jwt-go/blob/master/http_example_test.go#L107)
func keyFunc(token *jwt.Token) (interface{}, error) {
	return publicKey, nil
}

// This endpoint recieve a cookie from user (client)
// and verifies that the cookie is signed and unexpired
// it'll return the username itself as plain text if the cookie is ok
func verify(res http.ResponseWriter, r *http.Request) {

	// Get `token` cookie in the headers
	var jwtStringInCookie string
	requestCookies := r.Cookies()
	for _, cookie := range requestCookies {
		if cookie.Name == cookieKey {
			jwtStringInCookie = cookie.Value
		}
	}

	// Get username to verify somehow!
	username := r.Header.Get("x-username")

	if jwtStringInCookie == "" {
		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte("JWT token cookie is not provided in the request header"))
		return
	}
	if username == "" {
		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte("Username is not provided in the request header"))
		return
	}

	claims := jwt.StandardClaims{
		Subject: username,
	}
	token, err := jwt.ParseWithClaims(jwtStringInCookie, &claims, keyFunc)

	if err != nil {
		v, _ := err.(*jwt.ValidationError)

		// Respond to token expiraiton
		if v.Errors == jwt.ValidationErrorExpired {
			res.WriteHeader(http.StatusUnauthorized)
			res.Write([]byte(claims.Valid().Error()))
			return
		}

		res.WriteHeader(http.StatusBadRequest)
		res.Write([]byte("Failed to parse token " + claims.Valid().Error()))
		return
	}

	// Check the token validation at first
	if !token.Valid {
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("Token is not valid"))
		return
	}

	// Then check claims validation
	tokenClaim := token.Claims.(*jwt.StandardClaims)

	// Respond to different subjects(usernames)
	// (of course we can add more configs for some needs such as admin access)
	tokenSubjectOk := tokenClaim.Subject == username
	if !tokenSubjectOk {
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte("You're not allowed to use this token"))
		return
	}

	res.Write([]byte(username + " " + time.Unix(tokenClaim.ExpiresAt, 0).String()))
}

// This endpoint creates a JWT and sends it back to the user as a cookie.
// The body of the response will be the RSA public key in plain text.
func authHandler(res http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	jwtCookie, err := createToken(username)

	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte("Token Signing error: " + err.Error()))
		return
	}

	cookie := http.Cookie{Name: cookieKey, Value: jwtCookie}
	http.SetCookie(res, &cookie)

	pub := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2j3jHc7292PvBK9YafZfIB5cD2Ke+VUSfGWsP/zff0gkN6iqLt1VYziNxzSQnE7X1viunKUAEosfUokn9tRSSVcpwt+O+y/in3nNapjX0UA5f/dwlsJss3mRkrJF35JkFwJ6yDKRiFxdf4QXUjWYNlusUE9Im4heHx19TIXUoRqMZHrnudTntO0Ne3NhWfdcdOndes110PR28yUiH88r0Qmntix7GUC+oN3WiHPRIlv17znch7UqNedWThpxBWDufsgJa5CxzTRT27WQ5r+3vASDbcg4UMpIxYeAuzkIx2xEdp43fw5/BGbctjs9lMmpavCHgevZFAXhSmCcii0u9QIDAQAB"
	res.Write([]byte(pub))
}

func setPrivateAndPublicKeys() {
	setPrivateKey()
	setPublicKey()
}

func main() {

	// Initilize the RSA keys once
	setPrivateAndPublicKeys()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/verify", verify)
	r.Get("/auth/{username}", authHandler)

	http.ListenAndServe(":8080", r)
}
