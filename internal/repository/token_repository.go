package repository

import (
	"context"
	"fmt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

type TokenRepository interface {
	SaveAccessToken(ctx context.Context, token *domain.AccessToken) error
	GetAccessToken(ctx context.Context, token string) (*domain.AccessToken, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteExpiredAccessTokens(ctx context.Context) (int, error)

	SaveRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteExpiredRefreshTokens(ctx context.Context) (int, error)
}

type tokenRepository struct {
	store dao.TokenStore
}

func NewTokenRepository(store dao.TokenStore) TokenRepository {
	return &tokenRepository{store: store}
}

func (r *tokenRepository) SaveAccessToken(ctx context.Context, token *domain.AccessToken) error {
	daoToken := r.accessTokenToDAO(token)
	if err := r.store.SaveAccessToken(ctx, daoToken); err != nil {
		return fmt.Errorf("save access token failed: %w", err)
	}
	return nil
}

func (r *tokenRepository) GetAccessToken(ctx context.Context, token string) (*domain.AccessToken, error) {
	daoToken, err := r.store.GetAccessToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return r.daoToAccessToken(daoToken), nil
}

func (r *tokenRepository) DeleteAccessToken(ctx context.Context, token string) error {
	if err := r.store.DeleteAccessToken(ctx, token); err != nil {
		return fmt.Errorf("delete access token failed: %w", err)
	}
	return nil
}

func (r *tokenRepository) DeleteExpiredAccessTokens(ctx context.Context) (int, error) {
	count, err := r.store.DeleteExpiredAccessTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired access tokens failed: %w", err)
	}
	return count, nil
}

func (r *tokenRepository) SaveRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	daoToken := r.refreshTokenToDAO(token)
	if err := r.store.SaveRefreshToken(ctx, daoToken); err != nil {
		return fmt.Errorf("save refresh token failed: %w", err)
	}
	return nil
}

func (r *tokenRepository) GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	daoToken, err := r.store.GetRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return r.daoToRefreshToken(daoToken), nil
}

func (r *tokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	if err := r.store.RevokeRefreshToken(ctx, token); err != nil {
		return fmt.Errorf("revoke refresh token failed: %w", err)
	}
	return nil
}

func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	if err := r.store.DeleteRefreshToken(ctx, token); err != nil {
		return fmt.Errorf("delete refresh token failed: %w", err)
	}
	return nil
}

func (r *tokenRepository) DeleteExpiredRefreshTokens(ctx context.Context) (int, error) {
	count, err := r.store.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens failed: %w", err)
	}
	return count, nil
}

func (r *tokenRepository) accessTokenToDAO(token *domain.AccessToken) *dao.AccessToken {
	if token == nil {
		return nil
	}
	return &dao.AccessToken{
		Token:     token.Token,
		TokenType: token.TokenType,
		ClientId:  token.ClientId,
		UserId:    token.UserId,
		Scope:     token.Scope,
		ExpireAt:  token.ExpireAt,
		CreatedAt: token.CreatedAt,
	}
}

func (r *tokenRepository) daoToAccessToken(token *dao.AccessToken) *domain.AccessToken {
	if token == nil {
		return nil
	}
	return &domain.AccessToken{
		Token:     token.Token,
		TokenType: token.TokenType,
		ClientId:  token.ClientId,
		UserId:    token.UserId,
		Scope:     token.Scope,
		ExpireAt:  token.ExpireAt,
		CreatedAt: token.CreatedAt,
	}
}

func (r *tokenRepository) refreshTokenToDAO(token *domain.RefreshToken) *dao.RefreshToken {
	if token == nil {
		return nil
	}
	return &dao.RefreshToken{
		Token:     token.Token,
		ClientId:  token.ClientId,
		UserId:    token.UserId,
		Scope:     token.Scope,
		ExpireAt:  token.ExpireAt,
		CreatedAt: token.CreatedAt,
	}
}

func (r *tokenRepository) daoToRefreshToken(token *dao.RefreshToken) *domain.RefreshToken {
	if token == nil {
		return nil
	}
	return &domain.RefreshToken{
		Token:     token.Token,
		ClientId:  token.ClientId,
		UserId:    token.UserId,
		Scope:     token.Scope,
		ExpireAt:  token.ExpireAt,
		CreatedAt: token.CreatedAt,
	}
}
