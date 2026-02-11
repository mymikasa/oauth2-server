package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository"
)

type testContext struct {
	store       *inMemoryStore
	userService UserService
	oauth       OAuthService
	clientID    string
	userName    string
	password    string
}

func newTestContext(t *testing.T) *testContext {
	t.Helper()

	store := newInMemoryStore()
	userRepo := repository.NewUserRepository(store)
	userService := NewUserService(userRepo, UserConfig{BcryptCost: 4})

	clientSecretHash, err := bcrypt.GenerateFromPassword([]byte("client-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash client secret failed: %v", err)
	}

	clientRepo := repository.NewClientRepository(store)
	if err := clientRepo.CreateClient(context.Background(), &domain.Client{
		ID:          "client-1",
		Secret:      string(clientSecretHash),
		Name:        "demo",
		Description: "demo app",
		RedirectURI: "https://example.com/callback",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("create client failed: %v", err)
	}

	if _, err := userService.Register(context.Background(), RegisterRequest{
		Username: "alice",
		Password: "alice-password",
		Email:    "alice@example.com",
		NickName: "alice",
	}); err != nil {
		t.Fatalf("register default user failed: %v", err)
	}

	oauthConfig := DefaultOAuthConfig()
	oauthConfig.GlobalAllowedScopes = []string{"read", "write", "profile"}
	oauthConfig.ClientAllowedScopes = map[string][]string{
		"client-1": []string{"read", "profile"},
	}
	oauthConfig.DefaultScopes = []string{"read"}
	oauth := NewOAuthService(store, userService, oauthConfig)

	return &testContext{
		store:       store,
		userService: userService,
		oauth:       oauth,
		clientID:    "client-1",
		userName:    "alice",
		password:    "alice-password",
	}
}

func mustOAuthErrCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s but got nil", code)
	}
	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected OAuthError, got %T (%v)", err, err)
	}
	if oauthErr.Code != code {
		t.Fatalf("expected error code %s, got %s", code, oauthErr.Code)
	}
}

func pkceChallenge(verifier string) string {
	hashed := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hashed[:])
}
