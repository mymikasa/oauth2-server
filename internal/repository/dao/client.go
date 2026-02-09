package dao

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type Client struct {
	ID          uint64         `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	ClientId    string         `json:"client_id" gorm:"column:client_id;type:varchar(36);uniqueIndex;not null"`
	Secret      string         `json:"secret" gorm:"column:secret;type:varchar(255);not null"`
	Name        string         `json:"name" gorm:"column:name;type:varchar(100);not null"`
	Description string         `json:"description" gorm:"column:description;type:varchar(500)"`
	RedirectURI string         `json:"redirect_uri" gorm:"column:redirect_uri;type:varchar(500);not null"`
	LogoUrl     string         `json:"logo_url" gorm:"column:logo_url;type:varchar(500)"`
	CreatedAt   time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"column:deleted_at;index"`
}

func (Client) TableName() string {
	return "clients"
}

var (
	ErrClientNotFound = errors.New("client not found")
)

type clientStore struct {
	db *gorm.DB
}

func NewClientStore(db *gorm.DB) ClientStore {
	return &clientStore{db: db}
}

func (s *clientStore) CreateClient(ctx context.Context, client *Client) error {
	if err := s.db.WithContext(ctx).Create(client).Error; err != nil {
		return err
	}
	return nil
}

func (s *clientStore) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var client Client
	err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (s *clientStore) ListClients(ctx context.Context) ([]*Client, error) {
	var clients []*Client
	err := s.db.WithContext(ctx).Find(&clients).Error
	if err != nil {
		return nil, err
	}
	return clients, nil
}

func (s *clientStore) UpdateClient(ctx context.Context, client *Client) error {
	err := s.db.WithContext(ctx).Save(client).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *clientStore) DeleteClient(ctx context.Context, clientID string) error {
	result := s.db.WithContext(ctx).Where("client_id = ?", clientID).Delete(&Client{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrClientNotFound
	}
	return nil
}
