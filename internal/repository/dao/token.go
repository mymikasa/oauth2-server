package dao

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type AccessToken struct {
	ID        uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Token     string    `json:"token" gorm:"column:token;type:varchar(255);uniqueIndex;not null"`
	TokenType string    `json:"token_type" gorm:"column:token_type;type:varchar(50);default:'Bearer'"`
	ClientId  string    `json:"client_id" gorm:"column:client_id;type:varchar(36);not null;index"`
	UserId    string    `json:"user_id" gorm:"column:user_id;type:varchar(36);not null;index"`
	Scope     string    `json:"scope" gorm:"column:scope;type:varchar(500)"`
	ExpireAt  time.Time `json:"expire_at" gorm:"column:expire_at;not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

type RefreshToken struct {
	ID        uint64         `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Token     string         `json:"token" gorm:"column:token;type:varchar(255);uniqueIndex;not null"`
	ClientId  string         `json:"client_id" gorm:"column:client_id;type:varchar(36);not null;index"`
	UserId    string         `json:"user_id" gorm:"column:user_id;type:varchar(36);not null;index"`
	Scope     string         `json:"scope" gorm:"column:scope;type:varchar(500)"`
	Revoked   bool           `json:"revoked" gorm:"column:revoked;type:tinyint(1);default:0;index"`
	ExpireAt  time.Time      `json:"expire_at" gorm:"column:expire_at;not null;index"`
	CreatedAt time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"column:deleted_at;index"`
}

func (AccessToken) TableName() string {
	return "access_tokens"
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

var (
	ErrAccessTokenNotFound  = errors.New("access token not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenRevoked  = errors.New("refresh token already revoked")
)

type tokenStore struct {
	db *gorm.DB
}

func NewTokenStore(db *gorm.DB) TokenStore {
	return &tokenStore{db: db}
}

func (s *tokenStore) SaveAccessToken(ctx context.Context, token *AccessToken) error {
	if err := s.db.WithContext(ctx).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (s *tokenStore) GetAccessToken(ctx context.Context, token string) (*AccessToken, error) {
	var accessToken AccessToken
	err := s.db.WithContext(ctx).Where("token = ?", token).First(&accessToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAccessTokenNotFound
		}
		return nil, err
	}
	return &accessToken, nil
}

func (s *tokenStore) DeleteAccessToken(ctx context.Context, token string) error {
	result := s.db.WithContext(ctx).Where("token = ?", token).Delete(&AccessToken{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrAccessTokenNotFound
	}
	return nil
}

func (s *tokenStore) DeleteExpiredAccessTokens(ctx context.Context) (int, error) {
	result := s.db.WithContext(ctx).
		Where("expire_at < ?", time.Now()).
		Delete(&AccessToken{})

	return int(result.RowsAffected), result.Error
}

func (s *tokenStore) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	if err := s.db.WithContext(ctx).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (s *tokenStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var refreshToken RefreshToken
	err := s.db.WithContext(ctx).Where("token = ?", token).First(&refreshToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}
	if refreshToken.Revoked {
		return nil, ErrRefreshTokenRevoked
	}
	return &refreshToken, nil
}

func (s *tokenStore) DeleteRefreshToken(ctx context.Context, token string) error {
	result := s.db.WithContext(ctx).Where("token = ?", token).Delete(&RefreshToken{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRefreshTokenNotFound
	}
	return nil
}

func (s *tokenStore) DeleteExpiredRefreshTokens(ctx context.Context) (int, error) {
	result := s.db.WithContext(ctx).
		Where("expire_at < ?", time.Now()).
		Delete(&RefreshToken{})

	return int(result.RowsAffected), result.Error
}
