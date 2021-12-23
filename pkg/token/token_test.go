package token_test

// this is a integration test, not unit can be run without end point
import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tuxiot/keycloakclient/pkg/token"
)

func TestGetPublicKey(t *testing.T) {
	key, err := token.GetPublicKey("xxx", "xxx") // replace your server url and claim here

	assert.Nil(t, err)
	assert.NotEmpty(t, key)
}

func TestVerifyToken(t *testing.T) {
	tokenString := "XXXX"                       // replace your token here
	key, err := token.GetPublicKey("xxx", "xx") // replace your server url and claim here
	assert.Nil(t, err)

	token, err := token.VerifyToken(tokenString, key)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
}
