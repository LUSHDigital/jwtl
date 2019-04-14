package tokens

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pborman/uuid"
)

var (
	// ErrTokenMalformed is the message to return for a malformed token.
	ErrTokenMalformed = errors.New("token malformed")

	// ErrTokenExpired is the message to return for an expired token.
	ErrTokenExpired = errors.New("token expired or not yet valid")

	// ErrTokenInvalid is the message to return for an invalid token.
	ErrTokenInvalid = errors.New("invalid token")
)

// ErrUnexpectedSigningMethod is thrown when parsing a JWT encounters an
// unexpected signature method.
type ErrUnexpectedSigningMethod struct {
	alg interface{}
}

func (e *ErrUnexpectedSigningMethod) Error() string {
	return fmt.Sprintf("unexpected signing method: %v", e.alg)
}

// JWT is the auth tokeniser for JSON Web Tokens.
type JWT struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	authIssuer string
}

// claims hold the JWT claims to user for a token.
type claims struct {
	Consumer *Consumer `json:"consumer"`
	jwt.StandardClaims
}

// NewJWT returns a new JWT instance.
func NewJWT(bPrivateKey, bPublicKey, issuer string) (*JWT, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(bPrivateKey))
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(bPublicKey))
	if err != nil {
		return nil, err
	}

	return &JWT{
		privateKey: privateKey,
		publicKey:  publicKey,
		authIssuer: issuer,
	}, nil
}

// GenerateToken generates and returns an authentication token.
func (j *JWT) GenerateToken(consumer *Consumer) (*AuthToken, error) {
	// Create our claims. Note the consumer is sanitised.
	consumerClaims := claims{
		&Consumer{
			ID:        consumer.ID,
			FirstName: consumer.FirstName,
			LastName:  consumer.LastName,
			Language:  consumer.Language,
			Grants:    consumer.Grants,
		},
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			Issuer:    j.authIssuer,
			Id:        uuid.New(),
		},
	}

	// Create the token.
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, consumerClaims)

	// Sign the token.
	signedToken, err := newToken.SignedString(j.privateKey)
	if err != nil {
		return nil, err
	}

	// Prepare the token object.
	authToken := &AuthToken{
		Type:  "jwt",
		Value: signedToken,
	}

	return authToken, nil
}

// ValidateToken validates an authentication token and returns true/false
// based upon the result.
func (j *JWT) ValidateToken(t *AuthToken) (bool, error) {
	// Parse the JWT token.
	authToken, err := jwt.ParseWithClaims(t.Value, &claims{}, func(aToken *jwt.Token) (interface{}, error) {
		// Ensure the signing method was not changed.
		if _, ok := aToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &ErrUnexpectedSigningMethod{aToken.Header["alg"]}
		}

		return j.publicKey, nil
	})

	// Bail out if the token could not be parsed.
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			// Handle any token specific errors.
			if err.(*jwt.ValidationError).Errors&jwt.ValidationErrorMalformed != 0 {
				err = ErrTokenMalformed
			} else if err.(*jwt.ValidationError).Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				err = ErrTokenExpired
			} else {
				err = ErrTokenInvalid
			}

			return false, err
		}

		return false, err
	}

	// Check the claims and token are valid.
	if _, ok := authToken.Claims.(*claims); ok && authToken.Valid {
		return true, nil
	}

	return false, ErrTokenInvalid
}

// GetTokenConsumer returns the consumer details for a given auth token.
func (j *JWT) GetTokenConsumer(t *AuthToken) *Consumer {
	// Parse the JWT token.
	authToken, _ := jwt.ParseWithClaims(t.Value, &claims{}, func(aToken *jwt.Token) (interface{}, error) {
		// Ensure the signing method was not changed.
		if _, ok := aToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &ErrUnexpectedSigningMethod{aToken.Header["alg"]}
		}

		return j.publicKey, nil
	})

	// Check the claims and token are valid.
	if authClaims, ok := authToken.Claims.(*claims); ok {
		return authClaims.Consumer
	}

	return nil
}

// GetTokenExpiry returns the expiry date for a given auth token.
func (j *JWT) GetTokenExpiry(t *AuthToken) time.Time {
	var expiry time.Time

	// Parse the JWT token.
	authToken, _ := jwt.ParseWithClaims(t.Value, &claims{}, func(aToken *jwt.Token) (interface{}, error) {
		// Ensure the signing method was not changed.
		if _, ok := aToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &ErrUnexpectedSigningMethod{aToken.Header["alg"]}
		}

		return j.publicKey, nil
	})

	// Check the claims and token are valid.
	if authClaims, ok := authToken.Claims.(*claims); ok {
		expiry = time.Unix(authClaims.ExpiresAt, 0)
	}

	return expiry
}

// AuthToken represents an authentication token.
type AuthToken struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Consumer holds information about an API consumer.
type Consumer struct {
	ID        int         `json:"id"`               // The ID of the API consumer.
	FirstName string      `json:"first_name"`       // The first name of the consumer.
	LastName  string      `json:"last_name"`        // The last name of the consumer.
	Language  string      `json:"language"`         // The last name of the consumer.
	Roles     []int64     `json:"roles"`            // The role IDs that the consumer has.
	Grants    []string    `json:"grants,omitempty"` // The grants that the API consumer has.
	Tokens    []AuthToken `json:"tokens,omitempty"` // The API consumers current access token.
}

// HasGrants checks if a consumer possess any of a given set of grants?
func (c *Consumer) HasGrants(grants []string) bool {
	// Compare the consumers grants with the grants of the service resource.
	for _, grant := range grants {
		// If this grant exists in the users grants, we're good to go.
		for _, g := range c.Grants {
			if grant == g {
				return true
			}
		}
	}

	return false
}

// SanitisedConsumer holds sanitised information about an API consumer.
type SanitisedConsumer struct {
	ID        int         `json:"id"`               // The ID of the API consumer.
	FirstName string      `json:"first_name"`       // The first name of the consumer.
	LastName  string      `json:"last_name"`        // The last name of the consumer.
	Language  string      `json:"language"`         // The last name of the consumer.
	Tokens    []AuthToken `json:"tokens,omitempty"` // The API consumers current access token.
	Roles     []int64     `json:"roles"`            // The role IDs that the consumer has.
}
