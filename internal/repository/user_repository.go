package repository

import (
	"context"
	"fmt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *domain.User) error
	GetUser(ctx context.Context, id string) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	ListUsers(ctx context.Context) ([]*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	DeleteUser(ctx context.Context, id string) error
}

type userRepository struct {
	store dao.UserStore
}

func NewUserRepository(store dao.UserStore) UserRepository {
	return &userRepository{store: store}
}

func (r *userRepository) CreateUser(ctx context.Context, user *domain.User) error {
	daoUser := r.domainToDAO(user)
	if err := r.store.CreateUser(ctx, daoUser); err != nil {
		return fmt.Errorf("create user failed: %w", err)
	}
	return nil
}

func (r *userRepository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	daoUser, err := r.store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoUser), nil
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	daoUser, err := r.store.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoUser), nil
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	daoUser, err := r.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoUser), nil
}

func (r *userRepository) ListUsers(ctx context.Context) ([]*domain.User, error) {
	daoUsers, err := r.store.ListUser(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]*domain.User, len(daoUsers))
	for i, daoUser := range daoUsers {
		users[i] = r.daoToDomain(daoUser)
	}
	return users, nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	daoUser := r.domainToDAO(user)
	if err := r.store.UpdateUser(ctx, daoUser); err != nil {
		return fmt.Errorf("update user failed: %w", err)
	}
	return nil
}

func (r *userRepository) DeleteUser(ctx context.Context, id string) error {
	if err := r.store.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("delete user failed: %w", err)
	}
	return nil
}

func (r *userRepository) domainToDAO(user *domain.User) *dao.User {
	if user == nil {
		return nil
	}
	return &dao.User{
		UserId:    user.ID,
		Username:  user.Username,
		Password:  user.Password,
		Email:     user.Email,
		NickName:  user.NickName,
		CreatedAt: user.CreatedAt,
	}
}

func (r *userRepository) daoToDomain(user *dao.User) *domain.User {
	if user == nil {
		return nil
	}
	return &domain.User{
		ID:        user.UserId,
		Username:  user.Username,
		Password:  user.Password,
		Email:     user.Email,
		NickName:  user.NickName,
		CreatedAt: user.CreatedAt,
	}
}
