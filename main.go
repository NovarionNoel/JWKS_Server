// had a lot of help from ChatGPT debugging but still cannot get key expiry to make the test client happy
package main

//turns out external packages are kinda nice
import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// some fixed values
const (
	port              = 8080
	keySize           = 2048
	jwtExpiryDuration = time.Hour
)

// proper key struct
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	Expiry     time.Time
}

// makes my jwt library happier
type CustomClaims struct {
	jwt.StandardClaims
}

// attempt to handle key expiry
var keyPairs []*KeyPair
var expiredKeyPair *KeyPair

// make am RSA key with pub/priv
func generateRSAKeyPair() *KeyPair {
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	kid := base64.StdEncoding.EncodeToString(privKey.PublicKey.N.Bytes()[:6])
	expiry := time.Now().Add(jwtExpiryDuration)

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		Kid:        kid,
		Expiry:     expiry,
	}
}

// jwks endpoint
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keys := []map[string]interface{}{}

	for _, kp := range keyPairs {
		keys = append(keys, generateJWKFromKeyPair(kp))
		log.Println("Serving key with Kid:", kp.Kid) // Logging the kid for debugging
	}

	resp := map[string][]map[string]interface{}{
		"keys": keys,
	}

	json.NewEncoder(w).Encode(resp)
}

// create JWK pair
func generateJWKFromKeyPair(kp *KeyPair) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"kid": kp.Kid,
		"n":   base64.URLEncoding.EncodeToString(kp.PublicKey.N.Bytes()),
		"e":   "AQAB",
	}
}

// auth endpoint
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var targetKeyPair *KeyPair

	// Check if the 'expired' parameter is provided
	if r.URL.Query().Get("expired") != "" {
		// Use expired key for signing
		targetKeyPair = expiredKeyPair
	} else {
		// Normal case (use the most recent key)
		targetKeyPair = keyPairs[0]
	}

	expiry := time.Now().Add(jwtExpiryDuration)
	if r.URL.Query().Get("expired") != "" {
		expiry = time.Now().Add(-jwtExpiryDuration)
	}

	claims := &CustomClaims{
		jwt.StandardClaims{
			ExpiresAt: expiry.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = targetKeyPair.Kid
	log.Println("Signing JWT with Kid:", token.Header["kid"]) // Logging the kid for debugging

	signedToken, err := token.SignedString(targetKeyPair.PrivateKey)
	if err != nil {
		http.Error(w, "Error signing the token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(signedToken))
}

func main() {
	keyPairs = append(keyPairs, generateRSAKeyPair())

	// Create an expired key
	expiredKeyPair = generateRSAKeyPair()
	expiredKeyPair.Expiry = time.Now().Add(-jwtExpiryDuration)
	expiredKeyPair.Kid = "expiredKid"

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Printf("Server started on :%d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
