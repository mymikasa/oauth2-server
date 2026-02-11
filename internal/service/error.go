package service

import "fmt"

const (
	ErrCodeInvalidRequest     = "invalid_request"
	ErrCodeInvalidClient      = "invalid_client"
	ErrCodeInvalidGrant       = "invalid_grant"
	ErrCodeInvalidScope       = "invalid_scope"
	ErrCodeUnauthorizedClient = "unauthorized_client"
	ErrCodeServerError        = "server_error"
)

type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func newOAuthError(code, description string) error {
	return &OAuthError{
		Code:        code,
		Description: description,
	}
}
