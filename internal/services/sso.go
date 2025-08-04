package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type SSOService struct {
	db     *gorm.DB
	redis  *redis.Client
	logger *zap.Logger
	config *config.Config
}

func NewSSOService(db *gorm.DB, redis *redis.Client, logger *zap.Logger, cfg *config.Config) *SSOService {
	return &SSOService{
		db:     db,
		redis:  redis,
		logger: logger,
		config: cfg,
	}
}

func (s *SSOService) ListProviders(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.SSOProvider, int64, error) {
	var providers []*models.SSOProvider
	var total int64

	offset := (page - 1) * pageSize

	if err := s.db.WithContext(ctx).Model(&models.SSOProvider{}).Where("tenant_id = ?", tenantID).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count SSO providers: %w", err)
	}

	if err := s.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("priority DESC, created_at DESC").Offset(offset).Limit(pageSize).Find(&providers).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list SSO providers: %w", err)
	}

	return providers, total, nil
}

func (s *SSOService) CreateProvider(ctx context.Context, provider *models.SSOProvider) (*models.SSOProvider, error) {
	if provider.IsDefault {
		if err := s.db.WithContext(ctx).Model(&models.SSOProvider{}).Where("tenant_id = ? AND is_default = true", provider.TenantID).Update("is_default", false).Error; err != nil {
			return nil, fmt.Errorf("failed to update existing default provider: %w", err)
		}
	}

	if err := s.db.WithContext(ctx).Create(provider).Error; err != nil {
		return nil, fmt.Errorf("failed to create SSO provider: %w", err)
	}

	return provider, nil
}

func (s *SSOService) GetProvider(ctx context.Context, tenantID, providerID uuid.UUID) (*models.SSOProvider, error) {
	var provider models.SSOProvider
	if err := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", providerID, tenantID).First(&provider).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get SSO provider: %w", err)
	}

	return &provider, nil
}

func (s *SSOService) UpdateProvider(ctx context.Context, tenantID, providerID uuid.UUID, req *models.UpdateSSOProviderRequest) (*models.SSOProvider, error) {
	var provider models.SSOProvider
	if err := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", providerID, tenantID).First(&provider).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get SSO provider: %w", err)
	}

	updates := make(map[string]interface{})
	if req.ProviderName != nil {
		updates["provider_name"] = *req.ProviderName
	}
	if req.DisplayName != nil {
		updates["display_name"] = *req.DisplayName
	}
	if req.Configuration != nil {
		var newConfig models.SSOConfiguration
		if err := json.Unmarshal(*req.Configuration, &newConfig); err != nil {
			return nil, fmt.Errorf("invalid configuration format: %w", err)
		}
		if err := s.validateSSOConfiguration(newConfig, provider.ProviderType); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}

		var currentConfig models.SSOConfiguration
		if len(provider.Configuration) > 0 {
			_ = json.Unmarshal(provider.Configuration, &currentConfig)
		}

		updates["configuration"] = *req.Configuration
		s.logSSOConfigurationChanges(currentConfig, newConfig, provider.ID, ctx)
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.IsDefault != nil {
		if *req.IsDefault {
			if err := s.db.WithContext(ctx).Model(&models.SSOProvider{}).Where("tenant_id = ? AND is_default = true", tenantID).Update("is_default", false).Error; err != nil {
				return nil, fmt.Errorf("failed to update existing default provider: %w", err)
			}
		}
		updates["is_default"] = *req.IsDefault
	}
	if req.Priority != nil {
		updates["priority"] = *req.Priority
	}

	if len(updates) > 0 {
		if err := s.db.WithContext(ctx).Model(&provider).Updates(updates).Error; err != nil {
			return nil, fmt.Errorf("failed to update SSO provider: %w", err)
		}
	}

	return &provider, nil
}

func (s *SSOService) DeleteProvider(ctx context.Context, tenantID, providerID uuid.UUID) error {
	result := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", providerID, tenantID).Delete(&models.SSOProvider{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete SSO provider: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("SSO provider not found")
	}

	return nil
}

func (s *SSOService) TestConnection(ctx context.Context, tenantID, providerID uuid.UUID, req *models.TestSSOProviderRequest) (*models.SSOTestResult, error) {
	provider, err := s.GetProvider(ctx, tenantID, providerID)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, fmt.Errorf("SSO provider not found")
	}

	startTime := time.Now()
	testResult := &models.SSOTestResult{
		TestedAt:     startTime,
		ResponseTime: 0,
		Success:      false,
	}

	switch provider.ProviderType {
	case models.SSOProviderTypeSAML:
		testResult = s.testSAMLConnection(ctx, provider, req)
	case models.SSOProviderTypeOIDC:
		testResult = s.testOIDCConnection(ctx, provider, req)
	default:
		testResult.Error = fmt.Sprintf("Unsupported provider type: %s", provider.ProviderType)
	}

	testResult.ResponseTime = time.Since(startTime).Milliseconds()

	provider.LastTested = &startTime
	if testResultJSON, err := json.Marshal(testResult); err == nil {
		provider.TestResult = datatypes.JSON(testResultJSON)
	}
	s.db.WithContext(ctx).Save(provider)

	return testResult, nil
}

func (s *SSOService) testSAMLConnection(ctx context.Context, provider *models.SSOProvider, req *models.TestSSOProviderRequest) *models.SSOTestResult {
	result := &models.SSOTestResult{
		TestedAt: time.Now(),
		Success:  false,
	}

	var config models.SSOConfiguration
	if err := json.Unmarshal(provider.Configuration, &config); err != nil {
		result.Error = fmt.Sprintf("Failed to unmarshal SAML configuration: %v", err)
		return result
	}

	if config.SAML == nil {
		result.Error = "SAML configuration not found"
		return result
	}

	samlConfig := config.SAML

	resp, err := http.Get(samlConfig.SSOServiceURL)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to connect to SAML endpoint: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("SAML endpoint returned status %d", resp.StatusCode)
		return result
	}

	result.ConnectionSuccess = true
	result.Success = true
	result.Details = "SAML endpoint is accessible"

	return result
}

func (s *SSOService) testOIDCConnection(ctx context.Context, provider *models.SSOProvider, req *models.TestSSOProviderRequest) *models.SSOTestResult {
	result := &models.SSOTestResult{
		TestedAt: time.Now(),
		Success:  false,
	}

	var config models.SSOConfiguration
	if err := json.Unmarshal(provider.Configuration, &config); err != nil {
		result.Error = fmt.Sprintf("Failed to unmarshal OIDC configuration: %v", err)
		return result
	}

	if config.OIDC == nil {
		result.Error = "OIDC configuration not found"
		return result
	}

	oidcConfig := config.OIDC

	resp, err := http.Get(oidcConfig.IssuerURL + "/.well-known/openid_configuration")
	if err != nil {
		result.Error = fmt.Sprintf("Failed to connect to OIDC discovery endpoint: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("OIDC discovery endpoint returned status %d", resp.StatusCode)
		return result
	}

	result.ConnectionSuccess = true
	result.Success = true
	result.Details = "OIDC discovery endpoint is accessible"

	return result
}

func (s *SSOService) validateSSOConfiguration(config models.SSOConfiguration, providerType models.SSOProviderType) error {
	if providerType == models.SSOProviderTypeOIDC {
		if config.OIDC == nil {
			return fmt.Errorf("OIDC configuration is required for OIDC providers")
		}
		if config.OIDC.ClientID == "" {
			return fmt.Errorf("client_id is required for OIDC providers")
		}
		if config.OIDC.ClientSecret == "" {
			return fmt.Errorf("client_secret is required for OIDC providers")
		}
		if config.OIDC.IssuerURL == "" {
			return fmt.Errorf("issuer_url is required for OIDC providers")
		}
	}

	if providerType == models.SSOProviderTypeSAML {
		if config.SAML == nil {
			return fmt.Errorf("SAML configuration is required for SAML providers")
		}
		if config.SAML.EntityID == "" {
			return fmt.Errorf("entity_id is required for SAML providers")
		}
		if config.SAML.SSOServiceURL == "" {
			return fmt.Errorf("sso_service_url is required for SAML providers")
		}
	}

	return nil
}

func (s *SSOService) logSSOConfigurationChanges(oldConfig, newConfig models.SSOConfiguration, providerID uuid.UUID, ctx context.Context) {
	changes := make(map[string]interface{})

	if oldConfig.OIDC != nil && newConfig.OIDC != nil {
		if oldConfig.OIDC.ClientID != newConfig.OIDC.ClientID {
			changes["oidc_client_id"] = "[REDACTED]"
		}
		if oldConfig.OIDC.ClientSecret != newConfig.OIDC.ClientSecret {
			changes["oidc_client_secret"] = "[REDACTED]"
		}
		if oldConfig.OIDC.IssuerURL != newConfig.OIDC.IssuerURL {
			changes["oidc_issuer_url"] = newConfig.OIDC.IssuerURL
		}
	}

	if oldConfig.SAML != nil && newConfig.SAML != nil {
		if oldConfig.SAML.EntityID != newConfig.SAML.EntityID {
			changes["saml_entity_id"] = newConfig.SAML.EntityID
		}
		if oldConfig.SAML.SSOServiceURL != newConfig.SAML.SSOServiceURL {
			changes["saml_sso_service_url"] = newConfig.SAML.SSOServiceURL
		}
	}

	if (oldConfig.OIDC == nil) != (newConfig.OIDC == nil) {
		changes["oidc_config"] = "[UPDATED]"
	}
	if (oldConfig.SAML == nil) != (newConfig.SAML == nil) {
		changes["saml_config"] = "[UPDATED]"
	}

	if len(changes) > 0 {
		s.logger.Info("SSO configuration updated",
			zap.String("provider_id", providerID.String()),
			zap.Any("changes", changes))
	}
}
