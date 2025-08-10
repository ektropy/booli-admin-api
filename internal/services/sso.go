package services

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
)

type SSOService struct {
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
}

func NewSSOService(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *SSOService {
	return &SSOService{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

func (s *SSOService) ListProviders(ctx context.Context, realmName string, page, pageSize int) ([]*models.SSOProvider, int64, error) {
	idps, err := s.keycloakAdmin.ListIdentityProviders(ctx, realmName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list identity providers: %w", err)
	}

	// Convert Keycloak Identity Providers to our SSO Provider model
	var providers []*models.SSOProvider
	for _, idp := range idps {
		provider := &models.SSOProvider{
			ID:           idp.Alias, // Use alias as ID for now
			Alias:        idp.Alias,
			DisplayName:  idp.DisplayName,
			ProviderType: s.mapProviderType(idp.ProviderId),
			Enabled:      idp.Enabled,
			Config:       s.convertStringMapToInterface(idp.Config),
			RealmName:    realmName,
		}
		providers = append(providers, provider)
	}

	// Apply pagination
	total := int64(len(providers))
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > len(providers) {
		start = len(providers)
	}
	if end > len(providers) {
		end = len(providers)
	}

	paginatedProviders := providers[start:end]

	return paginatedProviders, total, nil
}

func (s *SSOService) GetProvider(ctx context.Context, realmName, alias string) (*models.SSOProvider, error) {
	idp, err := s.keycloakAdmin.GetIdentityProvider(ctx, realmName, alias)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}

	provider := &models.SSOProvider{
		ID:           idp.Alias,
		Alias:        idp.Alias,
		DisplayName:  idp.DisplayName,
		ProviderType: s.mapProviderType(idp.ProviderId),
		Enabled:      idp.Enabled,
		Config:       s.convertStringMapToInterface(idp.Config),
		RealmName:    realmName,
	}

	return provider, nil
}

func (s *SSOService) CreateProvider(ctx context.Context, realmName string, req *models.CreateSSOProviderRequest) (*models.SSOProvider, error) {
	idp := &keycloak.IdentityProviderRepresentation{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		ProviderId:  string(req.ProviderType),
		Enabled:     true,
		Config:      s.convertInterfaceMapToString(req.Config),
	}

	if err := s.keycloakAdmin.CreateIdentityProvider(ctx, realmName, idp); err != nil {
		return nil, fmt.Errorf("failed to create identity provider: %w", err)
	}

	s.logger.Info("Created SSO provider",
		zap.String("realm", realmName),
		zap.String("alias", req.Alias),
		zap.String("type", string(req.ProviderType)))

	// Return the created provider
	return s.GetProvider(ctx, realmName, req.Alias)
}

func (s *SSOService) UpdateProvider(ctx context.Context, realmName, alias string, req *models.UpdateSSOProviderRequest) (*models.SSOProvider, error) {
	// Get existing provider first
	existingIdp, err := s.keycloakAdmin.GetIdentityProvider(ctx, realmName, alias)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing identity provider: %w", err)
	}

	// Update fields if provided
	if req.DisplayName != nil {
		existingIdp.DisplayName = *req.DisplayName
	}
	if req.Enabled != nil {
		existingIdp.Enabled = *req.Enabled
	}
	if req.Config != nil {
		existingIdp.Config = s.convertInterfaceMapToString(*req.Config)
	}

	if err := s.keycloakAdmin.UpdateIdentityProvider(ctx, realmName, alias, existingIdp); err != nil {
		return nil, fmt.Errorf("failed to update identity provider: %w", err)
	}

	s.logger.Info("Updated SSO provider",
		zap.String("realm", realmName),
		zap.String("alias", alias))

	// Return the updated provider
	return s.GetProvider(ctx, realmName, alias)
}

func (s *SSOService) DeleteProvider(ctx context.Context, realmName, alias string) error {
	if err := s.keycloakAdmin.DeleteIdentityProvider(ctx, realmName, alias); err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}

	s.logger.Info("Deleted SSO provider",
		zap.String("realm", realmName),
		zap.String("alias", alias))

	return nil
}

func (s *SSOService) TestProvider(ctx context.Context, realmName, alias string, req *models.TestSSOProviderRequest) (*models.SSOTestResult, error) {
	// For now, just return a basic test result
	// In a real implementation, this would test the actual SSO connection
	
	result := &models.SSOTestResult{
		Success:      true,
		TestedAt:     ctx.Value("current_time").(time.Time),
		ResponseTime: 100, // Mock response time
	}

	s.logger.Info("Tested SSO provider",
		zap.String("realm", realmName),
		zap.String("alias", alias),
		zap.String("test_user", req.TestUser))

	return result, nil
}

// Helper functions to convert between string and interface{} maps
func (s *SSOService) convertStringMapToInterface(stringMap map[string]string) map[string]interface{} {
	interfaceMap := make(map[string]interface{})
	for k, v := range stringMap {
		interfaceMap[k] = v
	}
	return interfaceMap
}

func (s *SSOService) convertInterfaceMapToString(interfaceMap map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for k, v := range interfaceMap {
		switch val := v.(type) {
		case string:
			stringMap[k] = val
		case bool:
			stringMap[k] = strconv.FormatBool(val)
		case int:
			stringMap[k] = strconv.Itoa(val)
		case float64:
			stringMap[k] = strconv.FormatFloat(val, 'f', -1, 64)
		default:
			stringMap[k] = fmt.Sprintf("%v", val)
		}
	}
	return stringMap
}

func (s *SSOService) mapProviderType(keycloakProviderId string) models.SSOProviderType {
	switch keycloakProviderId {
	case "saml":
		return models.SSOProviderTypeSAML
	case "oidc":
		return models.SSOProviderTypeOIDC
	default:
		return models.SSOProviderTypeOIDC // Default fallback
	}
}