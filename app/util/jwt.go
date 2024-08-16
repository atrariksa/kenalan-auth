package util

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var TokenDuration = time.Hour * 24 * 7

type claims struct {
	jwt.StandardClaims
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

func GenerateToken(email string) (string, error) {
	claims := claims{
		Email: email,
		Exp:   time.Now().Add(TokenDuration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte("secretKey"))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (string, error) {

	token, err := jwt.ParseWithClaims(tokenString, &claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte("secretKey"), nil
	})

	if err != nil {
		return "", errors.New(ErrInvalidToken)
	}

	if !token.Valid {
		return "", errors.New(ErrInvalidToken)
	}

	// type-assert `Claims` into a variable of the appropriate type
	claims := token.Claims.(*claims)
	return claims.Email, nil
}
