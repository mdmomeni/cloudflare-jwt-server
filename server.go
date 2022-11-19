package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
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

type Stats struct {
	Verify      []string `json:"/verify"`
	Auth        []string `json:"/auth"`
	DecodeTimes []int64  `json:"decode_times"`
	EncodeTimes []int64  `json:"encode_times"`
}

// Returns the expiration time of the token
func tokenExpiration() time.Time {
	// 24 hours
	return time.Now().AddDate(0, 0, 1)
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

// Since we only use the one private key to sign the tokens,
// we also only use its public counter part to verify
// [Resource](https://github.com/dgrijalva/jwt-go/blob/master/http_example_test.go#L107)
func keyFunc(token *jwt.Token) (interface{}, error) {
	return publicKey, nil
}

func createToken(username string) (string, error) {

	t1 := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   username,
		ExpiresAt: tokenExpiration().Unix(),
	})
	signedString, err := token.SignedString(privateKey)

	addTimeRecord("encode", time.Since(t1))
	addUserRecord(username, "/auth")

	return signedString, err
}

// Edits the `stats.json` and add the information
func addUserRecord(username string, path string) {
	content, err := ioutil.ReadFile("stats.json")
	if err != nil {
		log.Fatal(err)
	}
	var stats Stats
	unMarshalErr := json.Unmarshal(content, &stats)
	if unMarshalErr != nil {
		log.Fatal(unMarshalErr.Error())
	}

	if path == "/verify" {
		stats.Verify = append(stats.Verify, username)
	}
	if path == "/auth" {
		stats.Auth = append(stats.Auth, username)
	}

	bytes, marshalErr := json.Marshal(stats)
	if marshalErr != nil {
		log.Fatal(marshalErr.Error())
	}
	writeErr := ioutil.WriteFile("stats.json", bytes, 0644)
	if writeErr != nil {
		log.Fatal(err.Error())
	}
}

// This endpoint recieve a cookie from user (client)
// and verifies that the cookie is signed and unexpired
// it'll return the username itself as plain text if the cookie is ok
func verify(res http.ResponseWriter, r *http.Request) {

	// Get `token` cookie in the headers
	var (
		jwtStringInCookie string
		username          string
	)

	// Get the username and generated JWT from the cookies
	requestCookies := r.Cookies()
	for _, cookie := range requestCookies {

		if cookie.Name == cookieKey {
			jwtStringInCookie = cookie.Value
		}

		if cookie.Name == "username" {
			username = cookie.Value
		}
	}

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

	addUserRecord(username, "/verify")

	claims := jwt.StandardClaims{
		Subject: username,
	}

	t1 := time.Now()
	token, err := jwt.ParseWithClaims(jwtStringInCookie, &claims, keyFunc)
	addTimeRecord("decode", time.Since(t1))

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

	res.Write([]byte(username))
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

	// Setting cookie path to `/` leads to access it from -
	// all the server routes
	tokenCookie := http.Cookie{Name: cookieKey, Value: jwtCookie, Path: "/"}
	userCookie := http.Cookie{Name: "username", Value: username, Path: "/verify"}
	http.SetCookie(res, &tokenCookie)
	http.SetCookie(res, &userCookie)

	pub := ""
	res.Write([]byte(pub))
}

func addTimeRecord(mode string, time time.Duration) {
	ms := time.Milliseconds()

	content, err := ioutil.ReadFile("stats.json")
	if err != nil {
		log.Fatal(err)
	}
	var stats Stats
	unMarshalErr := json.Unmarshal(content, &stats)
	if unMarshalErr != nil {
		log.Fatal(unMarshalErr.Error())
	}

	if mode == "encode" {
		stats.EncodeTimes = append(stats.EncodeTimes, ms)
	}
	if mode == "decode" {
		stats.DecodeTimes = append(stats.DecodeTimes, ms)
	}

	bytes, marshalErr := json.Marshal(stats)
	if marshalErr != nil {
		log.Fatal(marshalErr.Error())
	}
	writeErr := ioutil.WriteFile("stats.json", bytes, 0644)
	if writeErr != nil {
		log.Fatal(err.Error())
	}
}

func occuranceDict(arr []string) map[string]int {
	dict := make(map[string]int)
	for _, num := range arr {
		dict[num] = dict[num] + 1
	}
	return dict
}

// Returns the avrage value of an array of `floats`
func arrayMean(arr []int64) float64 {
	n := 4
	sum := 0
	for _, n := range arr {
		sum += int(n)
	}
	mean := (float64(sum)) / (float64(n))
	return math.Round((mean * 1000) / 1000)
}

func statsSorter(stats Stats) ([]byte, error) {
	dict := make(map[string]interface{})
	dict["auth"] = occuranceDict(stats.Auth)
	dict["verify"] = occuranceDict(stats.Verify)
	dict["avg_encode_time_ms"] = arrayMean(stats.EncodeTimes)
	dict["avg_decode_time_ms"] = arrayMean(stats.DecodeTimes)
	return json.Marshal(dict)
}

func statsHandler(res http.ResponseWriter, r *http.Request) {
	text, err := ioutil.ReadFile("stats.json")
	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(err.Error()))
	}
	res.Header().Add("Content-Type", "application/json")
	var stats Stats
	json.Unmarshal(text, &stats)
	result, _ := statsSorter(stats)
	res.Write(result)
}

func sendReadMe(res http.ResponseWriter, r *http.Request) {
	text, err := ioutil.ReadFile("README.md")
	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(err.Error()))
	}
	res.Write([]byte(text))
}

func setPrivateAndPublicKeys() {
	setPrivateKey()
	setPublicKey()
}

func main() {

	setPrivateAndPublicKeys()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/verify", verify)
	r.Get("/auth/{username}", authHandler)
	r.Get("/stats", statsHandler)
	r.Get("/README.txt", sendReadMe)

	http.ListenAndServe(":8080", r)
}
