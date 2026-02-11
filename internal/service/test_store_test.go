package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

type inMemoryData struct {
	usersByID       map[string]*dao.User
	userIDByName    map[string]string
	userIDByEmail   map[string]string
	clientsByID     map[string]*dao.Client
	authCodesByCode map[string]*dao.AuthorizationCode
	accessByToken   map[string]*dao.AccessToken
	refreshByToken  map[string]*dao.RefreshToken
}

type inMemoryStore struct {
	mu   *sync.Mutex
	data *inMemoryData
	tx   bool
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{
		mu: &sync.Mutex{},
		data: &inMemoryData{
			usersByID:       map[string]*dao.User{},
			userIDByName:    map[string]string{},
			userIDByEmail:   map[string]string{},
			clientsByID:     map[string]*dao.Client{},
			authCodesByCode: map[string]*dao.AuthorizationCode{},
			accessByToken:   map[string]*dao.AccessToken{},
			refreshByToken:  map[string]*dao.RefreshToken{},
		},
	}
}

func (s *inMemoryStore) WithTx(ctx context.Context, fn func(store dao.Store) error) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	txStore := &inMemoryStore{
		mu:   s.mu,
		data: s.data,
		tx:   true,
	}
	return fn(txStore)
}

func (s *inMemoryStore) lock() func() {
	if s.tx {
		return func() {}
	}
	s.mu.Lock()
	return s.mu.Unlock
}

func (s *inMemoryStore) CreateUser(ctx context.Context, user *dao.User) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.usersByID[user.UserId]; ok {
		return fmt.Errorf("duplicate user id")
	}
	if _, ok := s.data.userIDByName[user.Username]; ok {
		return fmt.Errorf("duplicate username")
	}
	if _, ok := s.data.userIDByEmail[user.Email]; ok {
		return fmt.Errorf("duplicate email")
	}
	u := *user
	s.data.usersByID[u.UserId] = &u
	s.data.userIDByName[u.Username] = u.UserId
	s.data.userIDByEmail[u.Email] = u.UserId
	return nil
}

func (s *inMemoryStore) GetUser(ctx context.Context, id string) (*dao.User, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	user, ok := s.data.usersByID[id]
	if !ok {
		return nil, dao.ErrUserNotFound
	}
	u := *user
	return &u, nil
}

func (s *inMemoryStore) GetUserByUsername(ctx context.Context, username string) (*dao.User, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	id, ok := s.data.userIDByName[username]
	if !ok {
		return nil, dao.ErrUserNotFound
	}
	user := s.data.usersByID[id]
	u := *user
	return &u, nil
}

func (s *inMemoryStore) GetUserByEmail(ctx context.Context, email string) (*dao.User, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	id, ok := s.data.userIDByEmail[email]
	if !ok {
		return nil, dao.ErrUserNotFound
	}
	user := s.data.usersByID[id]
	u := *user
	return &u, nil
}

func (s *inMemoryStore) ListUser(ctx context.Context) ([]*dao.User, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	users := make([]*dao.User, 0, len(s.data.usersByID))
	for _, user := range s.data.usersByID {
		u := *user
		users = append(users, &u)
	}
	return users, nil
}

func (s *inMemoryStore) UpdateUser(ctx context.Context, user *dao.User) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.usersByID[user.UserId]; !ok {
		return dao.ErrUserNotFound
	}
	u := *user
	s.data.usersByID[user.UserId] = &u
	s.data.userIDByName[user.Username] = user.UserId
	s.data.userIDByEmail[user.Email] = user.UserId
	return nil
}

func (s *inMemoryStore) DeleteUser(ctx context.Context, id string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	user, ok := s.data.usersByID[id]
	if !ok {
		return dao.ErrUserNotFound
	}
	delete(s.data.userIDByName, user.Username)
	delete(s.data.userIDByEmail, user.Email)
	delete(s.data.usersByID, id)
	return nil
}

func (s *inMemoryStore) CreateClient(ctx context.Context, client *dao.Client) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.clientsByID[client.ClientId]; ok {
		return fmt.Errorf("duplicate client")
	}
	c := *client
	s.data.clientsByID[client.ClientId] = &c
	return nil
}

func (s *inMemoryStore) GetClient(ctx context.Context, clientID string) (*dao.Client, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	client, ok := s.data.clientsByID[clientID]
	if !ok {
		return nil, dao.ErrClientNotFound
	}
	c := *client
	return &c, nil
}

func (s *inMemoryStore) ListClients(ctx context.Context) ([]*dao.Client, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	clients := make([]*dao.Client, 0, len(s.data.clientsByID))
	for _, client := range s.data.clientsByID {
		c := *client
		clients = append(clients, &c)
	}
	return clients, nil
}

func (s *inMemoryStore) UpdateClient(ctx context.Context, client *dao.Client) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.clientsByID[client.ClientId]; !ok {
		return dao.ErrClientNotFound
	}
	c := *client
	s.data.clientsByID[client.ClientId] = &c
	return nil
}

func (s *inMemoryStore) DeleteClient(ctx context.Context, clientID string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.clientsByID[clientID]; !ok {
		return dao.ErrClientNotFound
	}
	delete(s.data.clientsByID, clientID)
	return nil
}

func (s *inMemoryStore) SaveAuthCode(ctx context.Context, code *dao.AuthorizationCode) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.authCodesByCode[code.Code]; ok {
		return fmt.Errorf("duplicate auth code")
	}
	c := *code
	s.data.authCodesByCode[code.Code] = &c
	return nil
}

func (s *inMemoryStore) GetAuthCode(ctx context.Context, code string) (*dao.AuthorizationCode, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	authCode, ok := s.data.authCodesByCode[code]
	if !ok {
		return nil, dao.ErrAuthCodeNotFound
	}
	c := *authCode
	return &c, nil
}

func (s *inMemoryStore) ConsumeAuthCode(ctx context.Context, code string) (*dao.AuthorizationCode, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	authCode, ok := s.data.authCodesByCode[code]
	if !ok {
		return nil, dao.ErrAuthCodeNotFound
	}
	if authCode.Used {
		return nil, dao.ErrAuthCodeAlreadyUsed
	}
	if !authCode.ExpiresAt.After(time.Now()) {
		return nil, dao.ErrAuthCodeExpired
	}
	authCode.Used = true
	c := *authCode
	return &c, nil
}

func (s *inMemoryStore) MarkAuthCodeAsUsed(ctx context.Context, code string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	authCode, ok := s.data.authCodesByCode[code]
	if !ok {
		return dao.ErrAuthCodeNotFound
	}
	authCode.Used = true
	return nil
}

func (s *inMemoryStore) DeleteAuthCode(ctx context.Context, code string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.authCodesByCode[code]; !ok {
		return dao.ErrAuthCodeNotFound
	}
	delete(s.data.authCodesByCode, code)
	return nil
}

func (s *inMemoryStore) DeleteExpiredAuthCodes(ctx context.Context) (int, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	now := time.Now()
	count := 0
	for code, authCode := range s.data.authCodesByCode {
		if !authCode.ExpiresAt.After(now) {
			delete(s.data.authCodesByCode, code)
			count++
		}
	}
	return count, nil
}

func (s *inMemoryStore) SaveAccessToken(ctx context.Context, token *dao.AccessToken) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	t := *token
	s.data.accessByToken[token.Token] = &t
	return nil
}

func (s *inMemoryStore) GetAccessToken(ctx context.Context, token string) (*dao.AccessToken, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	accessToken, ok := s.data.accessByToken[token]
	if !ok {
		return nil, dao.ErrAccessTokenNotFound
	}
	t := *accessToken
	return &t, nil
}

func (s *inMemoryStore) DeleteAccessToken(ctx context.Context, token string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.accessByToken[token]; !ok {
		return dao.ErrAccessTokenNotFound
	}
	delete(s.data.accessByToken, token)
	return nil
}

func (s *inMemoryStore) DeleteExpiredAccessTokens(ctx context.Context) (int, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	now := time.Now()
	count := 0
	for token, accessToken := range s.data.accessByToken {
		if !accessToken.ExpireAt.After(now) {
			delete(s.data.accessByToken, token)
			count++
		}
	}
	return count, nil
}

func (s *inMemoryStore) SaveRefreshToken(ctx context.Context, token *dao.RefreshToken) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	t := *token
	s.data.refreshByToken[token.Token] = &t
	return nil
}

func (s *inMemoryStore) GetRefreshToken(ctx context.Context, token string) (*dao.RefreshToken, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	refreshToken, ok := s.data.refreshByToken[token]
	if !ok {
		return nil, dao.ErrRefreshTokenNotFound
	}
	if refreshToken.Revoked {
		return nil, dao.ErrRefreshTokenRevoked
	}
	t := *refreshToken
	return &t, nil
}

func (s *inMemoryStore) RevokeRefreshToken(ctx context.Context, token string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	refreshToken, ok := s.data.refreshByToken[token]
	if !ok {
		return dao.ErrRefreshTokenNotFound
	}
	if refreshToken.Revoked {
		return dao.ErrRefreshTokenRevoked
	}
	refreshToken.Revoked = true
	return nil
}

func (s *inMemoryStore) DeleteRefreshToken(ctx context.Context, token string) error {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	if _, ok := s.data.refreshByToken[token]; !ok {
		return dao.ErrRefreshTokenNotFound
	}
	delete(s.data.refreshByToken, token)
	return nil
}

func (s *inMemoryStore) DeleteExpiredRefreshTokens(ctx context.Context) (int, error) {
	_ = ctx
	unlock := s.lock()
	defer unlock()
	now := time.Now()
	count := 0
	for token, refreshToken := range s.data.refreshByToken {
		if !refreshToken.ExpireAt.After(now) {
			delete(s.data.refreshByToken, token)
			count++
		}
	}
	return count, nil
}
