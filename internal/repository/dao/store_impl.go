package dao

import (
	"context"

	"gorm.io/gorm"
)

type databaseStore struct {
	UserStore
	ClientStore
	AuthCodeStore
	TokenStore

	db *gorm.DB
}

func NewStore(db *gorm.DB) Store {
	return &databaseStore{
		UserStore:     NewUserStore(db),
		ClientStore:   NewClientStore(db),
		AuthCodeStore: NewAuthCodeStore(db),
		TokenStore:    NewTokenStore(db),
		db:            db,
	}
}

func (s *databaseStore) WithTx(ctx context.Context, fn func(store Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(NewStore(tx))
	})
}
