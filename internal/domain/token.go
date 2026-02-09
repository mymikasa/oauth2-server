package domain

import "time"

type AccessToken struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"` // 固定为 "Bearer"
	ClientId  string    `json:"client_id"`
	UserId    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpireAt  time.Time `json:"expire_at"`
	CreatedAt time.Time `json:"created_at"`
}

type RefreshToken struct {
	Token     string    `json:"token"`
	ClientId  string    `json:"client_id"`
	UserId    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpireAt  time.Time `json:"expire_at"`
	CreatedAt time.Time `json:"created_at"`
}
