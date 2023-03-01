package models

import "github.com/golang-jwt/jwt/v4"

type JWT struct {
	Header    string `json:"header"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Claims struct {
	Username       string `json:"username"`
	RegisterClaims jwt.MapClaims
}
