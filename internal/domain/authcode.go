package domain

import "time"

type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientId            string    `json:"client_id"`
	UserId              string    `json:"user_id"`
	RedirectUri         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	Used                bool      `json:"used"`
}
