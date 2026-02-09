package dao

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type AuthorizationCode struct {
	ID          uint64         `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Code        string         `json:"code" gorm:"column:code;type:varchar(255);uniqueIndex;not null"`
	ClientId    string         `json:"client_id" gorm:"column:client_id;type:varchar(36);not null;index"`
	UserId      string         `json:"user_id" gorm:"column:user_id;type:varchar(36);not null;index"`
	RedirectUri string         `json:"redirect_uri" gorm:"column:redirect_uri;type:varchar(500);not null"`
	Scope       string         `json:"scope" gorm:"column:scope;type:varchar(500)"`
	State       string         `json:"state" gorm:"column:state;type:varchar(255)"`
	ExpiresAt   time.Time      `json:"expires_at" gorm:"column:expires_at;not null;index"`
	Used        bool           `json:"used" gorm:"column:used;type:tinyint(1);default:0;index"`
	CreatedAt   time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"column:deleted_at;index"`
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

var (
	ErrAuthCodeNotFound    = errors.New("authorization code not found")
	ErrAuthCodeAlreadyUsed = errors.New("authorization code already used")
)

type authCodeStore struct {
	db *gorm.DB
}

func NewAuthCodeStore(db *gorm.DB) AuthCodeStore {
	return &authCodeStore{db: db}
}

func (s *authCodeStore) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	if err := s.db.WithContext(ctx).Create(code).Error; err != nil {
		return err
	}
	return nil
}

func (s *authCodeStore) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	var authCode AuthorizationCode
	err := s.db.WithContext(ctx).Where("code = ?", code).First(&authCode).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAuthCodeNotFound
		}
		return nil, err
	}
	return &authCode, nil
}

func (s *authCodeStore) MarkAuthCodeAsUsed(ctx context.Context, code string) error {
	result := s.db.WithContext(ctx).
		Where("code = ?", code).
		Update("used", true)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrAuthCodeNotFound
	}
	return nil
}

func (s *authCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	result := s.db.WithContext(ctx).Where("code = ?", code).Delete(&AuthorizationCode{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrAuthCodeNotFound
	}
	return nil
}

func (s *authCodeStore) DeleteExpiredAuthCodes(ctx context.Context) (int, error) {
	result := s.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&AuthorizationCode{})

	return int(result.RowsAffected), result.Error
}
