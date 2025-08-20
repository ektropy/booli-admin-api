package keycloak

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)


type IdentityProviderService struct {
	client *AdminClient
	logger *zap.Logger
}

func NewIdentityProviderService(client *AdminClient, logger *zap.Logger) *IdentityProviderService {
	return &IdentityProviderService{
		client: client,
		logger: logger,
	}
}

func (s *IdentityProviderService) CreateIdentityProvider(ctx context.Context, realm string, provider *IdentityProviderRepresentation) error {
	mappers := provider.Mappers
	provider.Mappers = nil
	
	err := s.client.CreateIdentityProvider(ctx, realm, provider)
	if err != nil {
		return fmt.Errorf("failed to create identity provider: %w", err)
	}

	s.logger.Info("Identity provider created successfully",
		zap.String("realm", realm),
		zap.String("alias", provider.Alias),
		zap.String("providerId", provider.ProviderId))

	for _, mapper := range mappers {
		mapper.IdentityProviderAlias = provider.Alias
		err := s.client.CreateIdentityProviderMapper(ctx, realm, provider.Alias, &mapper)
		if err != nil {
			s.logger.Error("Failed to create identity provider mapper",
				zap.String("realm", realm),
				zap.String("provider", provider.Alias),
				zap.String("mapper", mapper.Name),
				zap.Error(err))
		} else {
			s.logger.Info("Created identity provider mapper",
				zap.String("realm", realm),
				zap.String("provider", provider.Alias),
				zap.String("mapper", mapper.Name))
		}
	}

	return nil
}

func (s *IdentityProviderService) GetIdentityProvider(ctx context.Context, realm, alias string) (*IdentityProviderRepresentation, error) {
	provider, err := s.client.GetIdentityProvider(ctx, realm, alias)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}

	return provider, nil
}

func (s *IdentityProviderService) UpdateIdentityProvider(ctx context.Context, realm, alias string, provider *IdentityProviderRepresentation) error {
	err := s.client.UpdateIdentityProvider(ctx, realm, alias, provider)
	if err != nil {
		return fmt.Errorf("failed to update identity provider: %w", err)
	}

	s.logger.Info("Identity provider updated successfully",
		zap.String("realm", realm),
		zap.String("alias", alias))

	return nil
}

func (s *IdentityProviderService) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	err := s.client.DeleteIdentityProvider(ctx, realm, alias)
	if err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}

	s.logger.Info("Identity provider deleted successfully",
		zap.String("realm", realm),
		zap.String("alias", alias))

	return nil
}

func (s *IdentityProviderService) ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProviderRepresentation, error) {
	providers, err := s.client.ListIdentityProviders(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}

	return providers, nil
}

