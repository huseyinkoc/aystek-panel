package configs

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GetJWTSecret returns the signing key from environment
func GetJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "change_me_please"
	}
	return []byte(secret)
}

// Access token ömrü (saat cinsinden). Örn: JWT_EXPIRE_HOURS=24
func GetJWTExpiry() time.Duration {
	hoursStr := os.Getenv("JWT_EXPIRE_HOURS")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil || hours <= 0 {
		hours = 24
	}
	return time.Duration(hours) * time.Hour
}

// Refresh token ömrü (gün cinsinden). Örn: REFRESH_EXPIRE_DAYS=7
func GetRefreshExpiry() time.Duration {
	daysStr := os.Getenv("REFRESH_EXPIRE_DAYS")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		days = 7
	}
	return time.Duration(days) * 24 * time.Hour
}

// MyClaims custom JWT claims
type MyClaims struct {
	UserID string `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// CreateToken creates a signed JWT token
func CreateToken(userID, role string) (string, error) {
	exp := time.Now().Add(GetJWTExpiry())
	claims := MyClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "kwbsite",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(GetJWTSecret())
}

// ParseToken parses and validates a JWT
func ParseToken(tokenStr string) (*MyClaims, error) {
	claims := &MyClaims{}

	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return GetJWTSecret(), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		// v5’te error karşılaştırması doğrudan yapılır
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token not valid yet")
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, fmt.Errorf("malformed token")
		}
		return nil, err
	}

	return claims, nil
}
