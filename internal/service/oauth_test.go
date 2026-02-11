package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

func TestOAuthAuthorizeValidationAndSuccess(t *testing.T) {
	tc := newTestContext(t)
	verifier := "verifier-1"
	challenge := pkceChallenge(verifier)

	_, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            "missing-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-1",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidClient)

	_, err = tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://evil.example/callback",
		Scope:               "read",
		State:               "state-2",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidRequest)

	_, err = tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "write",
		State:               "state-3",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidScope)

	_, err = tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-4",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       "",
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidRequest)

	result, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read profile",
		State:               "state-5",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if result.Code == "" {
		t.Fatalf("authorization code should not be empty")
	}
}

func TestOAuthTokenByAuthorizationCode(t *testing.T) {
	tc := newTestContext(t)
	verifier := "verifier-2"
	challenge := pkceChallenge(verifier)

	auth, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-1",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	_, err = tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "bad-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: verifier,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidClient)

	_, err = tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://wrong.example/callback",
		CodeVerifier: verifier,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)

	auth, _ = tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-2",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	_, err = tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "wrong-verifier",
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)

	auth, _ = tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-3",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	pair, err := tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("token pair should include access and refresh token")
	}

	_, err = tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: verifier,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)
}

func TestOAuthRefreshTokenRotation(t *testing.T) {
	tc := newTestContext(t)
	verifier := "verifier-3"
	challenge := pkceChallenge(verifier)

	auth, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read profile",
		State:               "state-1",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	pair, err := tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	nextPair, err := tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeRefreshToken,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		RefreshToken: pair.RefreshToken,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("refresh token failed: %v", err)
	}
	if nextPair.RefreshToken == pair.RefreshToken {
		t.Fatalf("refresh token should be rotated")
	}

	_, err = tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeRefreshToken,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		RefreshToken: pair.RefreshToken,
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)
}

func TestOAuthAuthorizeCodeConcurrentConsume(t *testing.T) {
	tc := newTestContext(t)
	verifier := "verifier-4"
	challenge := pkceChallenge(verifier)

	auth, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-1",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	var successCount int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tc.oauth.Token(context.Background(), TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				ClientID:     tc.clientID,
				ClientSecret: "client-secret",
				Code:         auth.Code,
				RedirectURI:  "https://example.com/callback",
				CodeVerifier: verifier,
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&successCount); got != 1 {
		t.Fatalf("expected exactly one success, got %d", got)
	}
}

func TestOAuthRefreshConcurrentRotation(t *testing.T) {
	tc := newTestContext(t)
	verifier := "verifier-5"
	challenge := pkceChallenge(verifier)

	auth, err := tc.oauth.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            tc.clientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "read",
		State:               "state-1",
		Username:            tc.userName,
		Password:            tc.password,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCECodeMethodS256,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	pair, err := tc.oauth.Token(context.Background(), TokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     tc.clientID,
		ClientSecret: "client-secret",
		Code:         auth.Code,
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	var successCount int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tc.oauth.Token(context.Background(), TokenRequest{
				GrantType:    GrantTypeRefreshToken,
				ClientID:     tc.clientID,
				ClientSecret: "client-secret",
				RefreshToken: pair.RefreshToken,
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&successCount); got != 1 {
		t.Fatalf("expected exactly one success, got %d", got)
	}
}

func TestOAuthCleanupExpired(t *testing.T) {
	tc := newTestContext(t)
	now := time.Now()
	authCodeRepo := repository.NewAuthCodeRepository(tc.store)
	tokenRepo := repository.NewTokenRepository(tc.store)

	if err := authCodeRepo.SaveAuthCode(context.Background(), &domain.AuthorizationCode{
		Code:                "expired-auth",
		ClientId:            tc.clientID,
		UserId:              "user-1",
		RedirectUri:         "https://example.com/callback",
		Scope:               "read",
		State:               "state",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: PKCECodeMethodS256,
		ExpiresAt:           now.Add(-time.Minute),
		CreatedAt:           now.Add(-2 * time.Minute),
	}); err != nil {
		t.Fatalf("save auth code failed: %v", err)
	}
	if err := authCodeRepo.SaveAuthCode(context.Background(), &domain.AuthorizationCode{
		Code:                "valid-auth",
		ClientId:            tc.clientID,
		UserId:              "user-1",
		RedirectUri:         "https://example.com/callback",
		Scope:               "read",
		State:               "state",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: PKCECodeMethodS256,
		ExpiresAt:           now.Add(time.Hour),
		CreatedAt:           now,
	}); err != nil {
		t.Fatalf("save auth code failed: %v", err)
	}

	_ = tokenRepo.SaveAccessToken(context.Background(), &domain.AccessToken{
		Token:     "expired-access",
		TokenType: TokenTypeBearer,
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  now.Add(-time.Minute),
		CreatedAt: now.Add(-2 * time.Minute),
	})
	_ = tokenRepo.SaveAccessToken(context.Background(), &domain.AccessToken{
		Token:     "valid-access",
		TokenType: TokenTypeBearer,
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  now.Add(time.Hour),
		CreatedAt: now,
	})
	_ = tokenRepo.SaveRefreshToken(context.Background(), &domain.RefreshToken{
		Token:     "expired-refresh",
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  now.Add(-time.Minute),
		CreatedAt: now.Add(-2 * time.Minute),
	})
	_ = tokenRepo.SaveRefreshToken(context.Background(), &domain.RefreshToken{
		Token:     "valid-refresh",
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  now.Add(time.Hour),
		CreatedAt: now,
	})

	result, err := tc.oauth.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if result.AuthCodes != 1 || result.AccessTokens != 1 || result.RefreshTokens != 1 {
		t.Fatalf("unexpected cleanup count: %+v", result)
	}

	if _, err := authCodeRepo.GetAuthCode(context.Background(), "valid-auth"); err != nil {
		t.Fatalf("valid auth code should remain: %v", err)
	}
	if _, err := tokenRepo.GetAccessToken(context.Background(), "valid-access"); err != nil {
		t.Fatalf("valid access token should remain: %v", err)
	}
	if _, err := tokenRepo.GetRefreshToken(context.Background(), "valid-refresh"); err != nil {
		t.Fatalf("valid refresh token should remain: %v", err)
	}
}

func TestOAuthValidateAccessToken(t *testing.T) {
	tc := newTestContext(t)
	tokenRepo := repository.NewTokenRepository(tc.store)

	_ = tokenRepo.SaveAccessToken(context.Background(), &domain.AccessToken{
		Token:     "good-token",
		TokenType: TokenTypeBearer,
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})
	_ = tokenRepo.SaveAccessToken(context.Background(), &domain.AccessToken{
		Token:     "expired-token",
		TokenType: TokenTypeBearer,
		ClientId:  tc.clientID,
		UserId:    "user-1",
		Scope:     "read",
		ExpireAt:  time.Now().Add(-time.Minute),
		CreatedAt: time.Now().Add(-time.Hour),
	})

	claims, err := tc.oauth.ValidateAccessToken(context.Background(), "good-token")
	if err != nil {
		t.Fatalf("validate access token failed: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("unexpected user id: %s", claims.UserID)
	}

	_, err = tc.oauth.ValidateAccessToken(context.Background(), "expired-token")
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)
}

var _ dao.Store = (*inMemoryStore)(nil)
