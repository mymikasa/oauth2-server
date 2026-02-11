package dao

import "context"

type Store interface {
	UserStore
	ClientStore
	AuthCodeStore
	TokenStore
	WithTx(ctx context.Context, fn func(store Store) error) error
}

type UserStore interface {
	// CreateUser 创建用户
	CreateUser(ctx context.Context, user *User) error
	// GetUser 获取用户
	GetUser(ctx context.Context, id string) (*User, error)
	// GetUserByUsername 根据用户名获取用户
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// GetUserByEmail 根据邮箱获取用户
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// ListUser 获取所有用户
	ListUser(ctx context.Context) ([]*User, error)
	// UpdateUser 更新用户
	UpdateUser(ctx context.Context, user *User) error
	// DeleteUser 删除用户
	DeleteUser(ctx context.Context, id string) error
}

type ClientStore interface {
	// CreateClient 创建新客户端
	CreateClient(ctx context.Context, client *Client) error
	// GetClient 通过 client_id 获取客户端
	GetClient(ctx context.Context, clientID string) (*Client, error)
	// ListClients 获取所有客户端列表
	ListClients(ctx context.Context) ([]*Client, error)
	// UpdateClient 更新客户端信息
	UpdateClient(ctx context.Context, client *Client) error
	// DeleteClient 删除客户端
	DeleteClient(ctx context.Context, clientID string) error
}

type AuthCodeStore interface {
	// SaveAuthCode 保存授权码
	SaveAuthCode(ctx context.Context, code *AuthorizationCode) error
	// GetAuthCode 获取授权码
	GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error)
	// ConsumeAuthCode 原子消费授权码，仅未使用且未过期授权码可消费成功
	ConsumeAuthCode(ctx context.Context, code string) (*AuthorizationCode, error)
	// MarkAuthCodeAsUsed 标记授权码为已使用
	MarkAuthCodeAsUsed(ctx context.Context, code string) error
	// DeleteAuthCode 删除授权码
	DeleteAuthCode(ctx context.Context, code string) error
	// DeleteExpiredAuthCodes 删除所有过期的授权码
	DeleteExpiredAuthCodes(ctx context.Context) (int, error)
}

type TokenStore interface {
	// Access Token operations
	SaveAccessToken(ctx context.Context, token *AccessToken) error
	GetAccessToken(ctx context.Context, token string) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteExpiredAccessTokens(ctx context.Context) (int, error)

	// Refresh Token operations
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteExpiredRefreshTokens(ctx context.Context) (int, error)
}
