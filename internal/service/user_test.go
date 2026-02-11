package service

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/mymikasa/oauth2-server/internal/repository"
)

func TestUserServiceRegisterSuccess(t *testing.T) {
	store := newInMemoryStore()
	userSvc := NewUserService(repository.NewUserRepository(store), UserConfig{BcryptCost: 4})

	profile, err := userSvc.Register(context.Background(), RegisterRequest{
		Username: "bob",
		Password: "bob-password",
		Email:    "bob@example.com",
		NickName: "bob",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if profile.ID == "" {
		t.Fatalf("expected generated user id")
	}

	user, err := store.GetUserByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatalf("get user by username failed: %v", err)
	}
	if user.Password == "bob-password" {
		t.Fatalf("password should be hashed")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("bob-password")); err != nil {
		t.Fatalf("password hash validation failed: %v", err)
	}
}

func TestUserServiceRegisterDuplicate(t *testing.T) {
	store := newInMemoryStore()
	userSvc := NewUserService(repository.NewUserRepository(store), UserConfig{BcryptCost: 4})

	_, _ = userSvc.Register(context.Background(), RegisterRequest{
		Username: "bob",
		Password: "bob-password",
		Email:    "bob@example.com",
		NickName: "bob",
	})

	_, err := userSvc.Register(context.Background(), RegisterRequest{
		Username: "bob",
		Password: "another-password",
		Email:    "another@example.com",
		NickName: "bob-2",
	})
	mustOAuthErrCode(t, err, ErrCodeInvalidRequest)
}

func TestUserServiceAuthenticateWrongPassword(t *testing.T) {
	store := newInMemoryStore()
	userSvc := NewUserService(repository.NewUserRepository(store), UserConfig{BcryptCost: 4})

	_, _ = userSvc.Register(context.Background(), RegisterRequest{
		Username: "bob",
		Password: "bob-password",
		Email:    "bob@example.com",
		NickName: "bob",
	})

	_, err := userSvc.Authenticate(context.Background(), "bob", "wrong-password")
	mustOAuthErrCode(t, err, ErrCodeInvalidGrant)
}
