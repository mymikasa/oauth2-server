package dao

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint64         `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	UserId    string         `json:"user_id" gorm:"column:user_id;type:varchar(36);uniqueIndex;not null"`
	Username  string         `json:"username" gorm:"column:username;type:varchar(50);uniqueIndex;not null"`
	Password  string         `json:"-" gorm:"column:password;type:varchar(255);not null"`
	Email     string         `json:"email" gorm:"column:email;type:varchar(100);uniqueIndex;not null"`
	NickName  string         `json:"nick_name" gorm:"column:nick_name;type:varchar(100)"`
	CreatedAt time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"column:deleted_at;index"`
}

func (User) TableName() string {
	return "users"
}

var (
	ErrUserNotFound = errors.New("user not found")
)

type userStore struct {
	db *gorm.DB
}

func NewUserStore(db *gorm.DB) UserStore {
	return &userStore{db: db}
}

func (s *userStore) CreateUser(ctx context.Context, user *User) error {
	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		return err
	}
	return nil
}

func (s *userStore) GetUser(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("user_id = ?", id).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *userStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *userStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *userStore) ListUser(ctx context.Context) ([]*User, error) {
	var users []*User
	err := s.db.WithContext(ctx).Find(&users).Error
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (s *userStore) UpdateUser(ctx context.Context, user *User) error {
	err := s.db.WithContext(ctx).Save(user).Error
	if err != nil {
		return err
	}
	return nil
}

func (s *userStore) DeleteUser(ctx context.Context, id string) error {
	result := s.db.WithContext(ctx).Where("user_id = ?", id).Delete(&User{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}
