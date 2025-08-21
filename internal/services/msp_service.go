package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type MSPService struct {
	db                *gorm.DB
	keycloakAdmin     *keycloak.AdminClient
	permissionService *PermissionService
	logger            *zap.Logger
}

func NewMSPService(db *gorm.DB, keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *MSPService {
	permissionService := NewPermissionService(keycloakAdmin, logger)
	return &MSPService{
		db:                db,
		keycloakAdmin:     keycloakAdmin,
		permissionService: permissionService,
		logger:            logger,
	}
}

func (m *MSPService) CreateMSP(ctx context.Context, req *models.CreateMSPRequest) (*models.MSP, error) {
	m.logger.Info("Creating MSP",
		zap.String("name", req.Name),
		zap.String("realm_name", req.RealmName))

	if err := m.validateMSPRequest(req); err != nil {
		return nil, fmt.Errorf("invalid MSP request: %w", err)
	}

	clientPattern := req.ClientPattern
	if clientPattern == "" {
		clientPattern = m.generateClientPattern(req.RealmName)
	}

	settingsJSON, err := json.Marshal(req.Settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	msp := &models.MSP{
		RealmName:     req.RealmName,
		Name:          req.Name,
		Domain:        req.Domain,
		ClientPattern: clientPattern,
		Status:        models.MSPStatusActive,
		Settings:      settingsJSON,
	}

	if err := m.db.Create(msp).Error; err != nil {
		return nil, fmt.Errorf("failed to create MSP in database: %w", err)
	}

	if err := m.setupMSPInKeycloak(ctx, msp, req); err != nil {
		m.db.Delete(msp)
		return nil, fmt.Errorf("failed to setup MSP in Keycloak: %w", err)
	}

	m.logger.Info("MSP created successfully",
		zap.String("realm_name", msp.RealmName),
		zap.String("name", msp.Name))
	return msp, nil
}

func (m *MSPService) GetMSP(ctx context.Context, realmName string) (*models.MSP, error) {
	var msp models.MSP
	if err := m.db.Where("realm_name = ?", realmName).First(&msp).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("MSP not found: %s", realmName)
		}
		return nil, fmt.Errorf("failed to get MSP: %w", err)
	}
	return &msp, nil
}

func (m *MSPService) ListMSPs(ctx context.Context, page, pageSize int) (*models.MSPListResponse, error) {
	var msps []models.MSP
	var totalCount int64

	if err := m.db.Model(&models.MSP{}).Count(&totalCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count MSPs: %w", err)
	}

	offset := (page - 1) * pageSize
	if err := m.db.Offset(offset).Limit(pageSize).Find(&msps).Error; err != nil {
		return nil, fmt.Errorf("failed to list MSPs: %w", err)
	}

	return &models.MSPListResponse{
		MSPs:       msps,
		TotalCount: int(totalCount),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

func (m *MSPService) UpdateMSP(ctx context.Context, realmName string, req *models.UpdateMSPRequest) (*models.MSP, error) {
	msp, err := m.GetMSP(ctx, realmName)
	if err != nil {
		return nil, err
	}

	if req.Name != "" {
		msp.Name = req.Name
	}
	if req.Domain != "" {
		msp.Domain = req.Domain
	}
	if req.Status != "" {
		msp.Status = req.Status
	}
	
	if req.Settings.MaxClientTenants > 0 || req.Settings.MaxAdminUsers > 0 {
		settingsJSON, err := json.Marshal(req.Settings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal settings: %w", err)
		}
		msp.Settings = settingsJSON
	}

	if err := m.db.Save(msp).Error; err != nil {
		return nil, fmt.Errorf("failed to update MSP: %w", err)
	}

	m.logger.Info("MSP updated successfully", zap.String("realm_name", realmName))
	return msp, nil
}

func (m *MSPService) DeleteMSP(ctx context.Context, realmName string) error {
	msp, err := m.GetMSP(ctx, realmName)
	if err != nil {
		return err
	}

	clientTenants, err := m.GetMSPClientTenants(ctx, realmName, 1, 1000)
	if err != nil {
		return fmt.Errorf("failed to check client tenants: %w", err)
	}

	if len(clientTenants.Tenants) > 0 {
		return fmt.Errorf("cannot delete MSP with existing client tenants")
	}

	if err := m.keycloakAdmin.DeleteRealm(ctx, realmName); err != nil {
		m.logger.Warn("Failed to delete Keycloak realm", zap.String("realm", realmName), zap.Error(err))
	}

	if err := m.db.Delete(msp).Error; err != nil {
		return fmt.Errorf("failed to delete MSP: %w", err)
	}

	m.logger.Info("MSP deleted successfully", zap.String("realm_name", realmName))
	return nil
}

func (m *MSPService) AddMSPStaff(ctx context.Context, mspRealm string, req *models.AddMSPStaffRequest) (*models.MSPStaffMember, error) {
	m.logger.Info("Adding MSP staff member",
		zap.String("msp_realm", mspRealm),
		zap.String("username", req.Username),
		zap.String("role", req.Role))

	msp, err := m.GetMSP(ctx, mspRealm)
	if err != nil {
		return nil, err
	}

	if !msp.IsActive() {
		return nil, fmt.Errorf("cannot add staff to inactive MSP")
	}

	password := req.Password
	if password == "" {
		password = "TempPassword123!"
		req.Temporary = true
	}

	userRep := &keycloak.UserRepresentation{
		Username:      req.Username,
		Email:         req.Email,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Enabled:       true,
		EmailVerified: false,
		Credentials: []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     password,
				Temporary: req.Temporary,
			},
		},
	}

	createdUser, err := m.keycloakAdmin.CreateUser(ctx, mspRealm, userRep)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := m.permissionService.AssignUserRole(ctx, mspRealm, createdUser.ID, req.Role); err != nil {
		m.keycloakAdmin.DeleteUser(ctx, mspRealm, createdUser.ID)
		return nil, fmt.Errorf("failed to assign role: %w", err)
	}

	staffMember := &models.MSPStaffMember{
		UserID:    createdUser.ID,
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Roles:     []string{req.Role},
		Status:    "active",
		CreatedAt: "now",
	}

	m.logger.Info("MSP staff member added successfully",
		zap.String("msp_realm", mspRealm),
		zap.String("username", req.Username),
		zap.String("user_id", createdUser.ID))
	return staffMember, nil
}

func (m *MSPService) CreateClientTenant(ctx context.Context, mspRealm string, req *models.CreateClientTenantRequest) (*models.Tenant, error) {
	m.logger.Info("Creating client tenant for MSP",
		zap.String("msp_realm", mspRealm),
		zap.String("tenant_name", req.Name))

	msp, err := m.GetMSP(ctx, mspRealm)
	if err != nil {
		return nil, err
	}

	if !msp.CanManageClients() {
		return nil, fmt.Errorf("MSP cannot manage clients in current state")
	}

	clientRealmName := m.generateClientRealmName(msp, req.Name)

	settingsJSON, err := json.Marshal(req.Settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tenant settings: %w", err)
	}

	// Create tenant in database
	tenant := &models.Tenant{
		RealmName:  clientRealmName,
		Name:       req.Name,
		Domain:     req.Domain,
		Type:       models.TenantTypeClient,
		ParentMSP:  mspRealm,
		Status:     models.TenantStatusActive,
		Settings:   settingsJSON,
	}

	if err := m.db.Create(tenant).Error; err != nil {
		return nil, fmt.Errorf("failed to create tenant in database: %w", err)
	}

	// Create realm in Keycloak
	realmRep := &keycloak.RealmRepresentation{
		Realm:                 clientRealmName,
		Enabled:               true,
		DisplayName:           req.Name,
		LoginWithEmailAllowed: true,
		RegistrationAllowed:   false,
		ResetPasswordAllowed:  true,
		RememberMe:            true,
		VerifyEmail:           false,
	}

	if err := m.keycloakAdmin.CreateRealm(ctx, realmRep); err != nil {
		m.db.Delete(tenant)
		return nil, fmt.Errorf("failed to create realm in Keycloak: %w", err)
	}

	// Setup permissions for the new realm
	if err := m.permissionService.SetupRealmPermissions(ctx, clientRealmName); err != nil {
		m.keycloakAdmin.DeleteRealm(ctx, clientRealmName)
		m.db.Delete(tenant)
		return nil, fmt.Errorf("failed to setup realm permissions: %w", err)
	}

	m.logger.Info("Client tenant created successfully",
		zap.String("msp_realm", mspRealm),
		zap.String("client_realm", clientRealmName))
	return tenant, nil
}

func (m *MSPService) GetMSPClientTenants(ctx context.Context, mspRealm string, page, pageSize int) (*models.ClientTenantListResponse, error) {
	msp, err := m.GetMSP(ctx, mspRealm)
	if err != nil {
		return nil, err
	}

	var tenants []models.Tenant
	var totalCount int64

	query := m.db.Model(&models.Tenant{}).Where("type = ? AND realm_name LIKE ?", 
		models.TenantTypeClient, msp.GetClientRealmPrefix()+"%")

	if err := query.Count(&totalCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count client tenants: %w", err)
	}

	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Find(&tenants).Error; err != nil {
		return nil, fmt.Errorf("failed to list client tenants: %w", err)
	}

	return &models.ClientTenantListResponse{
		Tenants:    tenants,
		TotalCount: int(totalCount),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

func (m *MSPService) validateMSPRequest(req *models.CreateMSPRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.RealmName == "" {
		return fmt.Errorf("realm_name is required")
	}
	if req.AdminEmail == "" {
		return fmt.Errorf("admin_email is required")
	}
	if !strings.HasPrefix(req.RealmName, "msp-") {
		return fmt.Errorf("realm_name must start with 'msp-'")
	}
	return nil
}

func (m *MSPService) generateClientPattern(realmName string) string {
	if strings.HasPrefix(realmName, "msp-") {
		mspName := realmName[4:]
		return fmt.Sprintf("%s-client-", mspName)
	}
	return fmt.Sprintf("%s-client-", realmName)
}

func (m *MSPService) generateClientRealmName(msp *models.MSP, tenantName string) string {
	prefix := msp.GetClientRealmPrefix()
	safeName := strings.ToLower(strings.ReplaceAll(tenantName, " ", "-"))
	safeName = strings.ReplaceAll(safeName, "_", "-")
	return prefix + safeName
}

func (m *MSPService) setupMSPInKeycloak(ctx context.Context, msp *models.MSP, req *models.CreateMSPRequest) error {
	realmRep := &keycloak.RealmRepresentation{
		Realm:                 msp.RealmName,
		Enabled:               true,
		DisplayName:           msp.Name,
		LoginWithEmailAllowed: true,
		RegistrationAllowed:   false,
		ResetPasswordAllowed:  true,
		RememberMe:            true,
		VerifyEmail:           false,
	}

	if err := m.keycloakAdmin.CreateRealm(ctx, realmRep); err != nil {
		return fmt.Errorf("failed to create realm: %w", err)
	}

	if err := m.permissionService.SetupRealmPermissions(ctx, msp.RealmName); err != nil {
		return fmt.Errorf("failed to setup permissions: %w", err)
	}

	adminUserReq := &models.AddMSPStaffRequest{
		Username:  "admin",
		Email:     req.AdminEmail,
		FirstName: "MSP",
		LastName:  "Administrator",
		Role:      "msp-admin",
		Password:  "ChangeMe123!",
		Temporary: true,
	}

	_, err := m.AddMSPStaff(ctx, msp.RealmName, adminUserReq)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}