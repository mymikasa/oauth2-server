package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"

	TokenTypeBearer    = "Bearer"
	PKCECodeMethodS256 = "S256"

	defaultAccessTokenTTL  = 2 * time.Hour
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultAuthCodeTTL     = 5 * time.Minute
)

type OAuthConfig struct {
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	AuthCodeTTL         time.Duration
	GlobalAllowedScopes []string
	ClientAllowedScopes map[string][]string
	DefaultScopes       []string
}

func DefaultOAuthConfig() OAuthConfig {
	return OAuthConfig{
		AccessTokenTTL:      defaultAccessTokenTTL,
		RefreshTokenTTL:     defaultRefreshTokenTTL,
		AuthCodeTTL:         defaultAuthCodeTTL,
		GlobalAllowedScopes: nil,
		ClientAllowedScopes: map[string][]string{},
		DefaultScopes:       nil,
	}
}

type AuthorizeRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type AuthorizeResult struct {
	Code      string `json:"code"`
	State     string `json:"state"`
	ExpiresIn int64  `json:"expires_in"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

type AccessTokenClaims struct {
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CleanupResult struct {
	AuthCodes     int `json:"auth_codes"`
	AccessTokens  int `json:"access_tokens"`
	RefreshTokens int `json:"refresh_tokens"`
}

type OAuthService interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)
	Token(ctx context.Context, req TokenRequest) (*TokenPair, error)
	ValidateAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	CleanupExpired(ctx context.Context) (*CleanupResult, error)
}

type oauthService struct {
	store       dao.Store
	userService UserService
	cfg         OAuthConfig
	nowFn       func() time.Time
	tokenFn     func(byteLen int) (string, error)
}

func NewOAuthService(store dao.Store, userService UserService, cfg OAuthConfig) OAuthService {
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if cfg.AuthCodeTTL <= 0 {
		cfg.AuthCodeTTL = defaultAuthCodeTTL
	}
	if cfg.ClientAllowedScopes == nil {
		cfg.ClientAllowedScopes = map[string][]string{}
	}
	return &oauthService{
		store:       store,
		userService: userService,
		cfg:         cfg,
		nowFn:       time.Now,
		tokenFn:     generateSecureToken,
	}
}

func (s *oauthService) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error) {
	if req.ClientID == "" || req.RedirectURI == "" || req.Username == "" || req.Password == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "client_id, redirect_uri, username and password are required")
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != PKCECodeMethodS256 {
		return nil, newOAuthError(ErrCodeInvalidRequest, "code_challenge and code_challenge_method=S256 are required")
	}

	clientRepo := repository.NewClientRepository(s.store)
	client, err := clientRepo.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, dao.ErrClientNotFound) {
			return nil, newOAuthError(ErrCodeInvalidClient, "client not found")
		}
		return nil, fmt.Errorf("get client failed: %w", err)
	}
	if client.RedirectURI != req.RedirectURI {
		return nil, newOAuthError(ErrCodeInvalidRequest, "redirect_uri mismatch")
	}

	user, err := s.userService.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	scope, err := s.resolveScopes(client.ID, req.Scope, "")
	if err != nil {
		return nil, err
	}

	code, err := s.tokenFn(32)
	if err != nil {
		return nil, fmt.Errorf("generate authorization code failed: %w", err)
	}
	now := s.nowFn()
	authCode := &domain.AuthorizationCode{
		Code:                code,
		ClientId:            client.ID,
		UserId:              user.ID,
		RedirectUri:         req.RedirectURI,
		Scope:               scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           now.Add(s.cfg.AuthCodeTTL),
		CreatedAt:           now,
		Used:                false,
	}

	authCodeRepo := repository.NewAuthCodeRepository(s.store)
	if err := authCodeRepo.SaveAuthCode(ctx, authCode); err != nil {
		return nil, fmt.Errorf("save authorization code failed: %w", err)
	}

	return &AuthorizeResult{
		Code:      code,
		State:     req.State,
		ExpiresIn: int64(s.cfg.AuthCodeTTL.Seconds()),
	}, nil
}

func (s *oauthService) Token(ctx context.Context, req TokenRequest) (*TokenPair, error) {
	if req.GrantType != GrantTypeAuthorizationCode && req.GrantType != GrantTypeRefreshToken {
		return nil, newOAuthError(ErrCodeUnauthorizedClient, "unsupported grant_type")
	}

	client, err := s.authenticateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, client, req)
	case GrantTypeRefreshToken:
		return s.refreshByToken(ctx, client, req)
	default:
		return nil, newOAuthError(ErrCodeUnauthorizedClient, "unsupported grant_type")
	}
}

func (s *oauthService) ValidateAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	if token == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "access token is required")
	}

	tokenRepo := repository.NewTokenRepository(s.store)
	accessToken, err := tokenRepo.GetAccessToken(ctx, token)
	if err != nil {
		if errors.Is(err, dao.ErrAccessTokenNotFound) {
			return nil, newOAuthError(ErrCodeInvalidGrant, "invalid access token")
		}
		return nil, fmt.Errorf("get access token failed: %w", err)
	}

	if !accessToken.ExpireAt.After(s.nowFn()) {
		return nil, newOAuthError(ErrCodeInvalidGrant, "access token expired")
	}

	return &AccessTokenClaims{
		ClientID:  accessToken.ClientId,
		UserID:    accessToken.UserId,
		Scope:     accessToken.Scope,
		ExpiresAt: accessToken.ExpireAt,
	}, nil
}

func (s *oauthService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return newOAuthError(ErrCodeInvalidRequest, "refresh token is required")
	}

	tokenRepo := repository.NewTokenRepository(s.store)
	err := tokenRepo.RevokeRefreshToken(ctx, refreshToken)
	if err == nil {
		return nil
	}

	// 撤销接口采用幂等语义：不存在或已撤销都视为成功。
	if errors.Is(err, dao.ErrRefreshTokenNotFound) || errors.Is(err, dao.ErrRefreshTokenRevoked) {
		return nil
	}
	return fmt.Errorf("revoke refresh token failed: %w", err)
}

func (s *oauthService) CleanupExpired(ctx context.Context) (*CleanupResult, error) {
	authCodeRepo := repository.NewAuthCodeRepository(s.store)
	tokenRepo := repository.NewTokenRepository(s.store)

	authCodeCount, err := authCodeRepo.DeleteExpiredAuthCodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("delete expired auth codes failed: %w", err)
	}
	accessCount, err := tokenRepo.DeleteExpiredAccessTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("delete expired access tokens failed: %w", err)
	}
	refreshCount, err := tokenRepo.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("delete expired refresh tokens failed: %w", err)
	}

	return &CleanupResult{
		AuthCodes:     authCodeCount,
		AccessTokens:  accessCount,
		RefreshTokens: refreshCount,
	}, nil
}

func (s *oauthService) exchangeAuthorizationCode(ctx context.Context, client *domain.Client, req TokenRequest) (*TokenPair, error) {
	if req.Code == "" || req.RedirectURI == "" || req.CodeVerifier == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "code, redirect_uri and code_verifier are required")
	}

	var pair TokenPair
	err := s.store.WithTx(ctx, func(txStore dao.Store) error {
		authCodeRepo := repository.NewAuthCodeRepository(txStore)
		tokenRepo := repository.NewTokenRepository(txStore)

		authCode, err := authCodeRepo.ConsumeAuthCode(ctx, req.Code)
		if err != nil {
			return mapAuthCodeError(err)
		}
		if authCode.ClientId != client.ID {
			return newOAuthError(ErrCodeInvalidGrant, "authorization code client mismatch")
		}
		if authCode.RedirectUri != req.RedirectURI {
			return newOAuthError(ErrCodeInvalidGrant, "redirect_uri mismatch")
		}
		if authCode.CodeChallengeMethod != PKCECodeMethodS256 {
			return newOAuthError(ErrCodeInvalidGrant, "unsupported code challenge method")
		}
		if !verifyPKCES256(authCode.CodeChallenge, req.CodeVerifier) {
			return newOAuthError(ErrCodeInvalidGrant, "invalid code_verifier")
		}

		accessToken, refreshToken, err := s.issueTokens(authCode.ClientId, authCode.UserId, authCode.Scope)
		if err != nil {
			return fmt.Errorf("issue tokens failed: %w", err)
		}
		if err := tokenRepo.SaveAccessToken(ctx, accessToken); err != nil {
			return fmt.Errorf("save access token failed: %w", err)
		}
		if err := tokenRepo.SaveRefreshToken(ctx, refreshToken); err != nil {
			return fmt.Errorf("save refresh token failed: %w", err)
		}

		pair = buildTokenPair(accessToken, refreshToken)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func (s *oauthService) refreshByToken(ctx context.Context, client *domain.Client, req TokenRequest) (*TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, newOAuthError(ErrCodeInvalidRequest, "refresh_token is required")
	}

	var pair TokenPair
	err := s.store.WithTx(ctx, func(txStore dao.Store) error {
		tokenRepo := repository.NewTokenRepository(txStore)
		refreshToken, err := tokenRepo.GetRefreshToken(ctx, req.RefreshToken)
		if err != nil {
			return mapRefreshTokenError(err)
		}

		if refreshToken.ClientId != client.ID {
			return newOAuthError(ErrCodeInvalidGrant, "refresh token client mismatch")
		}
		if !refreshToken.ExpireAt.After(s.nowFn()) {
			return newOAuthError(ErrCodeInvalidGrant, "refresh token expired")
		}

		scope := refreshToken.Scope
		if strings.TrimSpace(req.Scope) != "" {
			requestedScope, err := s.resolveScopes(client.ID, req.Scope, "")
			if err != nil {
				return err
			}
			if !isScopeSubset(requestedScope, refreshToken.Scope) {
				return newOAuthError(ErrCodeInvalidScope, "requested scope exceeds original scope")
			}
			scope = requestedScope
		} else if strings.TrimSpace(scope) == "" {
			resolvedScope, err := s.resolveScopes(client.ID, "", "")
			if err != nil {
				return err
			}
			scope = resolvedScope
		}

		if err := tokenRepo.RevokeRefreshToken(ctx, req.RefreshToken); err != nil {
			return mapRefreshTokenError(err)
		}

		accessToken, newRefreshToken, err := s.issueTokens(client.ID, refreshToken.UserId, scope)
		if err != nil {
			return fmt.Errorf("issue tokens failed: %w", err)
		}
		if err := tokenRepo.SaveAccessToken(ctx, accessToken); err != nil {
			return fmt.Errorf("save access token failed: %w", err)
		}
		if err := tokenRepo.SaveRefreshToken(ctx, newRefreshToken); err != nil {
			return fmt.Errorf("save refresh token failed: %w", err)
		}

		pair = buildTokenPair(accessToken, newRefreshToken)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func (s *oauthService) authenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if clientID == "" || clientSecret == "" {
		return nil, newOAuthError(ErrCodeInvalidClient, "client_id and client_secret are required")
	}

	clientRepo := repository.NewClientRepository(s.store)
	client, err := clientRepo.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, dao.ErrClientNotFound) {
			return nil, newOAuthError(ErrCodeInvalidClient, "invalid client")
		}
		return nil, fmt.Errorf("get client failed: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(clientSecret)); err != nil {
		return nil, newOAuthError(ErrCodeInvalidClient, "invalid client")
	}
	return client, nil
}

func (s *oauthService) issueTokens(clientID, userID, scope string) (*domain.AccessToken, *domain.RefreshToken, error) {
	accessTokenString, err := s.tokenFn(32)
	if err != nil {
		return nil, nil, err
	}
	refreshTokenString, err := s.tokenFn(32)
	if err != nil {
		return nil, nil, err
	}

	now := s.nowFn()
	return &domain.AccessToken{
			Token:     accessTokenString,
			TokenType: TokenTypeBearer,
			ClientId:  clientID,
			UserId:    userID,
			Scope:     scope,
			ExpireAt:  now.Add(s.cfg.AccessTokenTTL),
			CreatedAt: now,
		}, &domain.RefreshToken{
			Token:     refreshTokenString,
			ClientId:  clientID,
			UserId:    userID,
			Scope:     scope,
			ExpireAt:  now.Add(s.cfg.RefreshTokenTTL),
			CreatedAt: now,
		}, nil
}

func (s *oauthService) resolveScopes(clientID, requestedScope, fallbackScope string) (string, error) {
	var scopes []string
	switch {
	case strings.TrimSpace(requestedScope) != "":
		scopes = parseScopes(requestedScope)
	case strings.TrimSpace(fallbackScope) != "":
		scopes = parseScopes(fallbackScope)
	default:
		scopes = dedupScopes(s.cfg.DefaultScopes)
	}

	if len(scopes) == 0 {
		return "", newOAuthError(ErrCodeInvalidScope, "scope is required")
	}

	globalAllowed := toScopeSet(s.cfg.GlobalAllowedScopes)
	clientAllowed, ok := s.cfg.ClientAllowedScopes[clientID]
	if !ok {
		return "", newOAuthError(ErrCodeInvalidScope, "client scope is not configured")
	}
	clientAllowedSet := toScopeSet(clientAllowed)

	for _, scope := range scopes {
		if _, ok := globalAllowed[scope]; !ok {
			return "", newOAuthError(ErrCodeInvalidScope, "scope is not allowed globally")
		}
		if _, ok := clientAllowedSet[scope]; !ok {
			return "", newOAuthError(ErrCodeInvalidScope, "scope is not allowed for client")
		}
	}
	return strings.Join(scopes, " "), nil
}

func buildTokenPair(accessToken *domain.AccessToken, refreshToken *domain.RefreshToken) TokenPair {
	return TokenPair{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
		TokenType:    accessToken.TokenType,
		Scope:        accessToken.Scope,
		ExpiresIn:    int64(accessToken.ExpireAt.Sub(accessToken.CreatedAt).Seconds()),
	}
}

func parseScopes(raw string) []string {
	return dedupScopes(strings.Fields(raw))
}

func dedupScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := set[scope]; ok {
			continue
		}
		set[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func toScopeSet(scopes []string) map[string]struct{} {
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	return set
}

func isScopeSubset(requestedScope, baseScope string) bool {
	reqSet := toScopeSet(parseScopes(requestedScope))
	baseSet := toScopeSet(parseScopes(baseScope))
	for scope := range reqSet {
		if _, ok := baseSet[scope]; !ok {
			return false
		}
	}
	return true
}

func verifyPKCES256(expectedChallenge, codeVerifier string) bool {
	hashed := sha256.Sum256([]byte(codeVerifier))
	actualChallenge := base64.RawURLEncoding.EncodeToString(hashed[:])
	return actualChallenge == expectedChallenge
}

func mapAuthCodeError(err error) error {
	if errors.Is(err, dao.ErrAuthCodeNotFound) ||
		errors.Is(err, dao.ErrAuthCodeAlreadyUsed) ||
		errors.Is(err, dao.ErrAuthCodeExpired) {
		return newOAuthError(ErrCodeInvalidGrant, "invalid authorization code")
	}
	return err
}

func mapRefreshTokenError(err error) error {
	if errors.Is(err, dao.ErrRefreshTokenNotFound) || errors.Is(err, dao.ErrRefreshTokenRevoked) {
		return newOAuthError(ErrCodeInvalidGrant, "invalid refresh token")
	}
	return err
}
