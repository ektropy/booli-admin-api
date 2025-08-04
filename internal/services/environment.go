package services

import (
	"context"
	"fmt"
	"time"

	"github.com/booli/booli-admin-api/internal/cache"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type EnvironmentService struct {
	db     *gorm.DB
	cache  cache.CacheInterface
	logger *zap.Logger
}

func NewEnvironmentService(db *gorm.DB, cache cache.CacheInterface, logger *zap.Logger) *EnvironmentService {
	return &EnvironmentService{
		db:     db,
		cache:  cache,
		logger: logger,
	}
}

func (s *EnvironmentService) CreateTenantEnvironment(ctx context.Context, req *models.CreateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	if req.TenantID == uuid.Nil {
		var tenant models.Tenant

		if req.TenantName != "" {
			if err := s.db.WithContext(ctx).Where("name = ?", req.TenantName).First(&tenant).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					return nil, fmt.Errorf("tenant not found with name: %s", req.TenantName)
				}
				return nil, fmt.Errorf("failed to lookup tenant by name: %w", err)
			}
		} else if req.TenantDomain != "" {
			if err := s.db.WithContext(ctx).Where("domain = ?", req.TenantDomain).First(&tenant).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					return nil, fmt.Errorf("tenant not found with domain: %s", req.TenantDomain)
				}
				return nil, fmt.Errorf("failed to lookup tenant by domain: %w", err)
			}
		} else {
			return nil, fmt.Errorf("tenant identifier is required (tenant_id, tenant_name, or tenant_domain)")
		}

		req.TenantID = tenant.ID
	}

	if err := s.validateTenantAccess(ctx, userTenantID, req.TenantID, models.AccessLevelReadWrite); err != nil {
		return nil, fmt.Errorf("access denied: %w", err)
	}

	if err := s.validateEnvironmentData(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	environment := &models.TenantEnvironment{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Environment: req.Environment,
		IsActive:    true,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(environment).Error; err != nil {
			return fmt.Errorf("failed to create environment: %w", err)
		}

		if len(req.NetworkRanges) > 0 {
			for i, nr := range req.NetworkRanges {
				req.NetworkRanges[i].EnvironmentID = environment.ID
				req.NetworkRanges[i].TenantID = environment.TenantID
				if err := models.ValidateCIDR(nr.CIDR); err != nil {
					return fmt.Errorf("invalid CIDR %s: %w", nr.CIDR, err)
				}
			}
			if err := tx.Create(&req.NetworkRanges).Error; err != nil {
				return fmt.Errorf("failed to create network ranges: %w", err)
			}
		}

		if len(req.PublicIPs) > 0 {
			for i, ip := range req.PublicIPs {
				req.PublicIPs[i].EnvironmentID = environment.ID
				req.PublicIPs[i].TenantID = environment.TenantID
				if err := models.ValidateIPAddress(ip.IPAddress); err != nil {
					return fmt.Errorf("invalid IP address %s: %w", ip.IPAddress, err)
				}
				req.PublicIPs[i].IPType = models.GetIPType(ip.IPAddress)
			}
			if err := tx.Create(&req.PublicIPs).Error; err != nil {
				return fmt.Errorf("failed to create public IPs: %w", err)
			}
		}

		if len(req.EgressIPs) > 0 {
			for i, ip := range req.EgressIPs {
				req.EgressIPs[i].EnvironmentID = environment.ID
				req.EgressIPs[i].TenantID = environment.TenantID
				if err := models.ValidateIPAddress(ip.IPAddress); err != nil {
					return fmt.Errorf("invalid egress IP address %s: %w", ip.IPAddress, err)
				}
				req.EgressIPs[i].IPType = models.GetIPType(ip.IPAddress)
			}
			if err := tx.Create(&req.EgressIPs).Error; err != nil {
				return fmt.Errorf("failed to create egress IPs: %w", err)
			}
		}

		if len(req.Domains) > 0 {
			for i, domain := range req.Domains {
				req.Domains[i].EnvironmentID = environment.ID
				req.Domains[i].TenantID = environment.TenantID
				if err := models.ValidateDomainName(domain.DomainName); err != nil {
					return fmt.Errorf("invalid domain %s: %w", domain.DomainName, err)
				}
			}
			if err := tx.Create(&req.Domains).Error; err != nil {
				return fmt.Errorf("failed to create domains: %w", err)
			}
		}

		if len(req.NamingConventions) > 0 {
			for i := range req.NamingConventions {
				req.NamingConventions[i].EnvironmentID = environment.ID
				req.NamingConventions[i].TenantID = environment.TenantID
			}
			if err := tx.Create(&req.NamingConventions).Error; err != nil {
				return fmt.Errorf("failed to create naming conventions: %w", err)
			}
		}

		if len(req.InfrastructureIPs) > 0 {
			for i, infra := range req.InfrastructureIPs {
				req.InfrastructureIPs[i].EnvironmentID = environment.ID
				req.InfrastructureIPs[i].TenantID = environment.TenantID
				if err := models.ValidateIPAddress(infra.IPAddress); err != nil {
					return fmt.Errorf("invalid infrastructure IP %s: %w", infra.IPAddress, err)
				}
			}
			if err := tx.Create(&req.InfrastructureIPs).Error; err != nil {
				return fmt.Errorf("failed to create infrastructure IPs: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return s.GetTenantEnvironment(ctx, environment.ID, userTenantID)
}

func (s *EnvironmentService) GetTenantEnvironment(ctx context.Context, environmentID, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	var environment models.TenantEnvironment

	query := s.db.WithContext(ctx).
		Preload("NetworkRanges").
		Preload("PublicIPs").
		Preload("EgressIPs").
		Preload("Domains").
		Preload("NamingConventions").
		Preload("InfrastructureIPs").
		Preload("AccessGrants").
		Where("id = ?", environmentID)

	if err := query.First(&environment).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("environment not found")
		}
		return nil, fmt.Errorf("failed to get environment: %w", err)
	}

	if err := s.validateTenantAccess(ctx, userTenantID, environment.TenantID, models.AccessLevelRead); err != nil {
		return nil, fmt.Errorf("access denied: %w", err)
	}

	return &environment, nil
}

func (s *EnvironmentService) ListTenantEnvironments(ctx context.Context, tenantID, userTenantID uuid.UUID, page, pageSize int) (*models.TenantEnvironmentListResponse, error) {
	if err := s.validateTenantAccess(ctx, userTenantID, tenantID, models.AccessLevelRead); err != nil {
		return nil, fmt.Errorf("access denied: %w", err)
	}

	offset := (page - 1) * pageSize

	var environments []models.TenantEnvironment
	var total int64

	if err := s.db.WithContext(ctx).Model(&models.TenantEnvironment{}).
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count environments: %w", err)
	}

	query := s.db.WithContext(ctx).
		Preload("NetworkRanges").
		Preload("PublicIPs").
		Preload("EgressIPs").
		Preload("Domains").
		Preload("NamingConventions").
		Preload("InfrastructureIPs").
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Order("created_at DESC").
		Offset(offset).
		Limit(pageSize)

	if err := query.Find(&environments).Error; err != nil {
		return nil, fmt.Errorf("failed to list environments: %w", err)
	}

	return &models.TenantEnvironmentListResponse{
		Environments: environments,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   (int(total) + pageSize - 1) / pageSize,
	}, nil
}

func (s *EnvironmentService) UpdateTenantEnvironment(ctx context.Context, environmentID uuid.UUID, req *models.UpdateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	var environment models.TenantEnvironment
	if err := s.db.WithContext(ctx).Where("id = ?", environmentID).First(&environment).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("environment not found")
		}
		return nil, fmt.Errorf("failed to get environment: %w", err)
	}

	if err := s.validateTenantAccess(ctx, userTenantID, environment.TenantID, models.AccessLevelReadWrite); err != nil {
		return nil, fmt.Errorf("access denied: %w", err)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updates := map[string]interface{}{}
		if req.Name != nil {
			updates["name"] = *req.Name
		}
		if req.Description != nil {
			updates["description"] = *req.Description
		}
		if req.Environment != nil {
			updates["environment"] = *req.Environment
		}
		if req.IsActive != nil {
			updates["is_active"] = *req.IsActive
		}

		if len(updates) > 0 {
			if err := tx.Model(&environment).Updates(updates).Error; err != nil {
				return fmt.Errorf("failed to update environment: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return s.GetTenantEnvironment(ctx, environmentID, userTenantID)
}

func (s *EnvironmentService) DeleteTenantEnvironment(ctx context.Context, environmentID, userTenantID uuid.UUID) error {
	var environment models.TenantEnvironment
	if err := s.db.WithContext(ctx).Where("id = ?", environmentID).First(&environment).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("environment not found")
		}
		return fmt.Errorf("failed to get environment: %w", err)
	}

	if err := s.validateTenantAccess(ctx, userTenantID, environment.TenantID, models.AccessLevelFullAccess); err != nil {
		return fmt.Errorf("access denied: %w", err)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.NetworkRange{}).Error; err != nil {
			return fmt.Errorf("failed to delete network ranges: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.PublicIP{}).Error; err != nil {
			return fmt.Errorf("failed to delete public IPs: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.EgressIP{}).Error; err != nil {
			return fmt.Errorf("failed to delete egress IPs: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.Domain{}).Error; err != nil {
			return fmt.Errorf("failed to delete domains: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.NamingConvention{}).Error; err != nil {
			return fmt.Errorf("failed to delete naming conventions: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.InfrastructureIP{}).Error; err != nil {
			return fmt.Errorf("failed to delete infrastructure IPs: %w", err)
		}
		if err := tx.Where("environment_id = ?", environmentID).Delete(&models.TenantAccessGrant{}).Error; err != nil {
			return fmt.Errorf("failed to delete access grants: %w", err)
		}

		if err := tx.Delete(&environment).Error; err != nil {
			return fmt.Errorf("failed to delete environment: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	s.clearEnvironmentCache(ctx, environment.TenantID.String(), environmentID.String())

	return nil
}

func (s *EnvironmentService) GrantTenantAccess(ctx context.Context, req *models.CreateTenantAccessGrantRequest, granterTenantID uuid.UUID) (*models.TenantAccessGrant, error) {
	environment, err := s.GetTenantEnvironment(ctx, req.EnvironmentID, granterTenantID)
	if err != nil {
		return nil, fmt.Errorf("cannot access target environment: %w", err)
	}

	grant := &models.TenantAccessGrant{
		EnvironmentID:     req.EnvironmentID,
		TenantID:          environment.TenantID,
		GrantedToUserID:   req.GrantedToUserID,
		GrantedToTenantID: req.GrantedToTenantID,
		AccessLevel:       req.AccessLevel,
		GrantedBy:         req.GrantedBy,
		ExpiresAt:         req.ExpiresAt,
		IsActive:          true,
	}

	if err := s.db.WithContext(ctx).Create(grant).Error; err != nil {
		return nil, fmt.Errorf("failed to create access grant: %w", err)
	}

	if err := s.db.WithContext(ctx).
		Preload("GrantedToUser").
		Preload("GrantedToTenant").
		Where("id = ?", grant.ID).
		First(grant).Error; err != nil {
		return nil, fmt.Errorf("failed to load access grant: %w", err)
	}

	return grant, nil
}

func (s *EnvironmentService) RevokeAccess(ctx context.Context, grantID, revokerTenantID uuid.UUID) error {
	var grant models.TenantAccessGrant
	if err := s.db.WithContext(ctx).Where("id = ?", grantID).First(&grant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("access grant not found")
		}
		return fmt.Errorf("failed to get access grant: %w", err)
	}

	if err := s.validateTenantAccess(ctx, revokerTenantID, grant.TenantID, models.AccessLevelFullAccess); err != nil {
		return fmt.Errorf("access denied: %w", err)
	}

	if err := s.db.WithContext(ctx).Delete(&grant).Error; err != nil {
		return fmt.Errorf("failed to revoke access: %w", err)
	}

	return nil
}

func (s *EnvironmentService) GetSIEMEnrichmentData(ctx context.Context, tenantID, userTenantID uuid.UUID) (*models.SIEMEnrichmentData, error) {
	if err := s.validateTenantAccess(ctx, userTenantID, tenantID, models.AccessLevelRead); err != nil {
		return nil, fmt.Errorf("access denied: %w", err)
	}

	mspAdminTenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	actualTenantID := tenantID

	if userTenantID == mspAdminTenantID {
		var tenantWithEnvironments models.Tenant
		if err := s.db.WithContext(ctx).
			Select("tenants.id").
			Joins("JOIN tenant_environments ON tenants.id = tenant_environments.tenant_id").
			Where("tenant_environments.is_active = ? AND tenant_environments.deleted_at IS NULL", true).
			Order("tenant_environments.created_at DESC").
			First(&tenantWithEnvironments).Error; err == nil {
			actualTenantID = tenantWithEnvironments.ID
		}
	}

	cacheKey := fmt.Sprintf("siem_enrichment:%s", actualTenantID.String())
	if cached, err := s.cache.Get(ctx, userTenantID.String(), cacheKey); err == nil && cached != "" {
		s.logger.Debug("Cache hit for SIEM enrichment data", zap.String("tenant_id", actualTenantID.String()))
	}

	var environments []models.TenantEnvironment
	if err := s.db.WithContext(ctx).
		Preload("NetworkRanges").
		Preload("PublicIPs").
		Preload("EgressIPs").
		Preload("Domains").
		Preload("InfrastructureIPs").
		Where("tenant_id = ? AND is_active = ? AND deleted_at IS NULL", actualTenantID, true).
		Find(&environments).Error; err != nil {
		return nil, fmt.Errorf("failed to get environments: %w", err)
	}

	enrichmentData := &models.SIEMEnrichmentData{
		TenantID:          actualTenantID,
		NetworkRanges:     []models.NetworkRange{},
		PublicIPs:         []models.PublicIP{},
		EgressIPs:         []models.EgressIP{},
		Domains:           []models.Domain{},
		InfrastructureIPs: []models.InfrastructureIP{},
		LastUpdated:       time.Now(), // Default to current time if no environments exist
	}

	if len(environments) > 0 {
		enrichmentData.LastUpdated = environments[0].UpdatedAt
	}

	for _, env := range environments {
		enrichmentData.NetworkRanges = append(enrichmentData.NetworkRanges, env.NetworkRanges...)
		enrichmentData.PublicIPs = append(enrichmentData.PublicIPs, env.PublicIPs...)
		enrichmentData.EgressIPs = append(enrichmentData.EgressIPs, env.EgressIPs...)
		enrichmentData.Domains = append(enrichmentData.Domains, env.Domains...)
		enrichmentData.InfrastructureIPs = append(enrichmentData.InfrastructureIPs, env.InfrastructureIPs...)

		if env.UpdatedAt.After(enrichmentData.LastUpdated) {
			enrichmentData.LastUpdated = env.UpdatedAt
		}
	}

	return enrichmentData, nil
}

func (s *EnvironmentService) validateTenantAccess(ctx context.Context, userTenantID, targetTenantID uuid.UUID, requiredLevel models.AccessLevel) error {
	mspAdminTenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if userTenantID == mspAdminTenantID {
		return nil
	}

	if userTenantID == targetTenantID {
		return nil
	}

	var targetTenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", targetTenantID).First(&targetTenant).Error; err == nil {
		if targetTenant.ParentTenantID != nil && *targetTenant.ParentTenantID == userTenantID {
			return nil
		}
	}

	var grant models.TenantAccessGrant
	err := s.db.WithContext(ctx).
		Where("granted_to_tenant_id = ? AND tenant_id = ? AND access_level IN (?, ?, ?) AND is_active = ? AND (expires_at IS NULL OR expires_at > NOW())",
			userTenantID, targetTenantID, requiredLevel, models.AccessLevelReadWrite, models.AccessLevelFullAccess, true).
		First(&grant).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("access denied: no permission to access tenant %s", targetTenantID)
		}
		return fmt.Errorf("failed to check access grants: %w", err)
	}

	return nil
}

func (s *EnvironmentService) validateEnvironmentData(req *models.CreateTenantEnvironmentRequest) error {
	if req.Name == "" {
		return fmt.Errorf("environment name is required")
	}

	for _, nr := range req.NetworkRanges {
		if err := models.ValidateCIDR(nr.CIDR); err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", nr.CIDR, err)
		}
	}

	for _, ip := range req.PublicIPs {
		if err := models.ValidateIPAddress(ip.IPAddress); err != nil {
			return fmt.Errorf("invalid public IP %s: %w", ip.IPAddress, err)
		}
	}

	for _, ip := range req.EgressIPs {
		if err := models.ValidateIPAddress(ip.IPAddress); err != nil {
			return fmt.Errorf("invalid egress IP %s: %w", ip.IPAddress, err)
		}
	}

	for _, ip := range req.InfrastructureIPs {
		if err := models.ValidateIPAddress(ip.IPAddress); err != nil {
			return fmt.Errorf("invalid infrastructure IP %s: %w", ip.IPAddress, err)
		}
	}

	for _, domain := range req.Domains {
		if err := models.ValidateDomainName(domain.DomainName); err != nil {
			return fmt.Errorf("invalid domain %s: %w", domain.DomainName, err)
		}
	}

	return nil
}

func (s *EnvironmentService) clearEnvironmentCache(ctx context.Context, tenantID, environmentID string) {
	cacheKeys := []string{
		fmt.Sprintf("siem_enrichment:%s", tenantID),
		fmt.Sprintf("environment:%s", environmentID),
		fmt.Sprintf("environment_list:%s", tenantID),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, tenantID, key); err != nil {
			s.logger.Warn("Failed to clear cache", zap.String("key", key), zap.Error(err))
		}
	}
}
