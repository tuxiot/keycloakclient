package token

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
)

const CERTS_URL = "%s/realms/%s/protocol/openid-connect/certs"

type Key struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	// X5t_S256 string   `json:"x5t#S256"`
}

type Keys struct {
	Keys []Key `json:"keys"`
}

func GetPublicKey(host string, realm string) (token string, err error) {
	endPoint := fmt.Sprintf(CERTS_URL, host, realm)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{}
	req, err := http.NewRequest("GET", endPoint, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	var keys Keys
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&keys)

	if err != nil {
		return "", err
	}

	for _, key := range keys.Keys {
		if key.Alg == "RS256" {
			return key.X5c[0], nil
		}
	}

	return "", fmt.Errorf("no public key found")

}

func VerifyToken(keycloakToken string, keyString string) (bool, error) {
	secretKey := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", keyString)

	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(secretKey))
	if err != nil {
		return false, err
	}

	token, err := jwt.Parse(keycloakToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return false, err
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, nil
	}

	return false, fmt.Errorf("token is invalid")
}
