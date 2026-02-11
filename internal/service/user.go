package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

const defaultBcryptCost = 12

type UserConfig struct {
	BcryptCost int
}

func DefaultUserConfig() UserConfig {
	return UserConfig{
		BcryptCost: defaultBcryptCost,
	}
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	NickName string `json:"nick_name"`
}

type UserProfile struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	NickName  string    `json:"nick_name"`
	CreatedAt time.Time `json:"created_at"`
}

type UserService interface {
	Register(ctx context.Context, req RegisterRequest) (*UserProfile, error)
	Authenticate(ctx context.Context, username, password string) (*UserProfile, error)
}

type userService struct {
	userRepo repository.UserRepository
	cfg      UserConfig
	nowFn    func() time.Time
	idFn     func() (string, error)
}

func NewUserService(userRepo repository.UserRepository, cfg UserConfig) UserService {
	if cfg.BcryptCost <= 0 {
		cfg.BcryptCost = defaultBcryptCost
	}
	return &userService{
		userRepo: userRepo,
		cfg:      cfg,
		nowFn:    time.Now,
		idFn: func() (string, error) {
			return generateSecureToken(18)
		},
	}
}

func (s *userService) Register(ctx context.Context, req RegisterRequest) (*UserProfile, error) {
	if req.Username == "" || req.Password == "" || req.Email == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "username, password and email are required")
	}

	_, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err == nil {
		return nil, newOAuthError(ErrCodeInvalidRequest, "username already exists")
	}
	if !errors.Is(err, dao.ErrUserNotFound) {
		return nil, fmt.Errorf("check username failed: %w", err)
	}

	_, err = s.userRepo.GetUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, newOAuthError(ErrCodeInvalidRequest, "email already exists")
	}
	if !errors.Is(err, dao.ErrUserNotFound) {
		return nil, fmt.Errorf("check email failed: %w", err)
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password failed: %w", err)
	}

	id, err := s.idFn()
	if err != nil {
		return nil, fmt.Errorf("generate user id failed: %w", err)
	}

	now := s.nowFn()
	user := &domain.User{
		ID:        id,
		Username:  req.Username,
		Password:  string(hashedPwd),
		Email:     req.Email,
		NickName:  req.NickName,
		CreatedAt: now,
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("create user failed: %w", err)
	}
	return toUserProfile(user), nil
}

func (s *userService) Authenticate(ctx context.Context, username, password string) (*UserProfile, error) {
	if username == "" || password == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "username and password are required")
	}

	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, dao.ErrUserNotFound) {
			return nil, newOAuthError(ErrCodeInvalidGrant, "invalid username or password")
		}
		return nil, fmt.Errorf("get user by username failed: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, newOAuthError(ErrCodeInvalidGrant, "invalid username or password")
	}
	return toUserProfile(user), nil
}

func toUserProfile(user *domain.User) *UserProfile {
	if user == nil {
		return nil
	}
	return &UserProfile{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		NickName:  user.NickName,
		CreatedAt: user.CreatedAt,
	}
}
