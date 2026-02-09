package repository

import (
	"context"
	"fmt"

	"github.com/mymikasa/oauth2-server/internal/domain"
	"github.com/mymikasa/oauth2-server/internal/repository/dao"
)

type ClientRepository interface {
	CreateClient(ctx context.Context, client *domain.Client) error
	GetClient(ctx context.Context, clientID string) (*domain.Client, error)
	ListClients(ctx context.Context) ([]*domain.Client, error)
	UpdateClient(ctx context.Context, client *domain.Client) error
	DeleteClient(ctx context.Context, clientID string) error
}

type clientRepository struct {
	store dao.ClientStore
}

func NewClientRepository(store dao.ClientStore) ClientRepository {
	return &clientRepository{store: store}
}

func (r *clientRepository) CreateClient(ctx context.Context, client *domain.Client) error {
	daoClient := r.domainToDAO(client)
	if err := r.store.CreateClient(ctx, daoClient); err != nil {
		return fmt.Errorf("create client failed: %w", err)
	}
	return nil
}

func (r *clientRepository) GetClient(ctx context.Context, clientID string) (*domain.Client, error) {
	daoClient, err := r.store.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return r.daoToDomain(daoClient), nil
}

func (r *clientRepository) ListClients(ctx context.Context) ([]*domain.Client, error) {
	daoClients, err := r.store.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	clients := make([]*domain.Client, len(daoClients))
	for i, daoClient := range daoClients {
		clients[i] = r.daoToDomain(daoClient)
	}
	return clients, nil
}

func (r *clientRepository) UpdateClient(ctx context.Context, client *domain.Client) error {
	daoClient := r.domainToDAO(client)
	if err := r.store.UpdateClient(ctx, daoClient); err != nil {
		return fmt.Errorf("update client failed: %w", err)
	}
	return nil
}

func (r *clientRepository) DeleteClient(ctx context.Context, clientID string) error {
	if err := r.store.DeleteClient(ctx, clientID); err != nil {
		return fmt.Errorf("delete client failed: %w", err)
	}
	return nil
}

func (r *clientRepository) domainToDAO(client *domain.Client) *dao.Client {
	if client == nil {
		return nil
	}
	return &dao.Client{
		ClientId:    client.ID,
		Secret:      client.Secret,
		Name:        client.Name,
		Description: client.Description,
		RedirectURI: client.RedirectURI,
		LogoUrl:     client.LogoUrl,
		CreatedAt:   client.CreatedAt,
	}
}

func (r *clientRepository) daoToDomain(client *dao.Client) *domain.Client {
	if client == nil {
		return nil
	}
	return &domain.Client{
		ID:          client.ClientId,
		Secret:      client.Secret,
		Name:        client.Name,
		Description: client.Description,
		RedirectURI: client.RedirectURI,
		CreatedAt:   client.CreatedAt,
		LogoUrl:     client.LogoUrl,
	}
}
