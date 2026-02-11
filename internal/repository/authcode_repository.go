package repository

import (
	"context"
	"fmt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

type AuthCodeRepository interface {
	SaveAuthCode(ctx context.Context, code *domain.AuthorizationCode) error
	GetAuthCode(ctx context.Context, code string) (*domain.AuthorizationCode, error)
	ConsumeAuthCode(ctx context.Context, code string) (*domain.AuthorizationCode, error)
	MarkAuthCodeAsUsed(ctx context.Context, code string) error
	DeleteAuthCode(ctx context.Context, code string) error
	DeleteExpiredAuthCodes(ctx context.Context) (int, error)
}

type authCodeRepository struct {
	store dao.AuthCodeStore
}

func NewAuthCodeRepository(store dao.AuthCodeStore) AuthCodeRepository {
	return &authCodeRepository{store: store}
}

func (r *authCodeRepository) SaveAuthCode(ctx context.Context, code *domain.AuthorizationCode) error {
	daoCode := r.domainToDAO(code)
	if err := r.store.SaveAuthCode(ctx, daoCode); err != nil {
		return fmt.Errorf("save auth code failed: %w", err)
	}
	return nil
}

func (r *authCodeRepository) GetAuthCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	daoCode, err := r.store.GetAuthCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoCode), nil
}

func (r *authCodeRepository) ConsumeAuthCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	daoCode, err := r.store.ConsumeAuthCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoCode), nil
}

func (r *authCodeRepository) MarkAuthCodeAsUsed(ctx context.Context, code string) error {
	if err := r.store.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return fmt.Errorf("mark auth code as used failed: %w", err)
	}
	return nil
}

func (r *authCodeRepository) DeleteAuthCode(ctx context.Context, code string) error {
	if err := r.store.DeleteAuthCode(ctx, code); err != nil {
		return fmt.Errorf("delete auth code failed: %w", err)
	}
	return nil
}

func (r *authCodeRepository) DeleteExpiredAuthCodes(ctx context.Context) (int, error) {
	count, err := r.store.DeleteExpiredAuthCodes(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired auth codes failed: %w", err)
	}
	return count, nil
}

func (r *authCodeRepository) domainToDAO(code *domain.AuthorizationCode) *dao.AuthorizationCode {
	if code == nil {
		return nil
	}
	return &dao.AuthorizationCode{
		Code:                code.Code,
		ClientId:            code.ClientId,
		UserId:              code.UserId,
		RedirectUri:         code.RedirectUri,
		Scope:               code.Scope,
		State:               code.State,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		ExpiresAt:           code.ExpiresAt,
		Used:                code.Used,
		CreatedAt:           code.CreatedAt,
	}
}

func (r *authCodeRepository) daoToDomain(code *dao.AuthorizationCode) *domain.AuthorizationCode {
	if code == nil {
		return nil
	}
	return &domain.AuthorizationCode{
		Code:                code.Code,
		ClientId:            code.ClientId,
		UserId:              code.UserId,
		RedirectUri:         code.RedirectUri,
		Scope:               code.Scope,
		State:               code.State,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		ExpiresAt:           code.ExpiresAt,
		CreatedAt:           code.CreatedAt,
		Used:                code.Used,
	}
}
