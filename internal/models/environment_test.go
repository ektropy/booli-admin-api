package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestTenantEnvironment_BeforeCreate(t *testing.T) {
	env := &TenantEnvironment{
		TenantID:    uuid.New(),
		Name:        "test-env",
		Description: "Test environment",
		Environment: "development",
	}
	
	// Simulate GORM's BeforeCreate hook
	db := &gorm.DB{} // Mock DB for the hook
	err := env.BeforeCreate(db)
	
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, env.ID)
}

func TestTenantEnvironment_Structure(t *testing.T) {
	envID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()
	
	env := &TenantEnvironment{
		ID:          envID,
		TenantID:    tenantID,
		Name:        "production",
		Description: "Production environment",
		Environment: "production",
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	
	assert.Equal(t, envID, env.ID)
	assert.Equal(t, tenantID, env.TenantID)
	assert.Equal(t, "production", env.Name)
	assert.Equal(t, "Production environment", env.Description)
	assert.Equal(t, "production", env.Environment)
	assert.True(t, env.IsActive)
	assert.Equal(t, now, env.CreatedAt)
	assert.Equal(t, now, env.UpdatedAt)
}

func TestCreateTenantEnvironmentRequest_Structure(t *testing.T) {
	tenantID := uuid.New()
	
	tests := []struct {
		name    string
		request CreateTenantEnvironmentRequest
		valid   bool
	}{
		{
			name: "Valid request",
			request: CreateTenantEnvironmentRequest{
				TenantID:    tenantID,
				Name:        "test-env",
				Description: "Test environment",
				Environment: "development",
			},
			valid: true,
		},
		{
			name: "Missing name",
			request: CreateTenantEnvironmentRequest{
				TenantID:    tenantID,
				Description: "Test environment",
				Environment: "development",
			},
			valid: false,
		},
		{
			name: "Empty name",
			request: CreateTenantEnvironmentRequest{
				TenantID:    tenantID,
				Name:        "",
				Description: "Test environment",
				Environment: "development",
			},
			valid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic structure validation - would need actual validator for field validation
			if tt.valid {
				assert.NotEmpty(t, tt.request.Name)
				assert.NotEqual(t, uuid.Nil, tt.request.TenantID)
			}
		})
	}
}

func TestUpdateTenantEnvironmentRequest_Structure(t *testing.T) {
	name := "updated-env"
	description := "Updated description"
	environment := "staging"
	isActive := false
	
	req := UpdateTenantEnvironmentRequest{
		Name:        &name,
		Description: &description,
		Environment: &environment,
		IsActive:    &isActive,
	}
	
	assert.NotNil(t, req.Name)
	assert.Equal(t, "updated-env", *req.Name)
	assert.NotNil(t, req.Description)
	assert.Equal(t, "Updated description", *req.Description)
	assert.NotNil(t, req.Environment)
	assert.Equal(t, "staging", *req.Environment)
	assert.NotNil(t, req.IsActive)
	assert.False(t, *req.IsActive)
}

func TestTenantEnvironmentListResponse_Structure(t *testing.T) {
	environments := []TenantEnvironment{
		{ID: uuid.New(), Name: "dev", IsActive: true},
		{ID: uuid.New(), Name: "prod", IsActive: true},
	}
	
	response := TenantEnvironmentListResponse{
		Environments: environments,
		Total:        100,
		Page:         1,
		PageSize:     20,
		TotalPages:   5,
	}
	
	assert.Len(t, response.Environments, 2)
	assert.Equal(t, int64(100), response.Total)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 20, response.PageSize)
	assert.Equal(t, 5, response.TotalPages)
}

func TestNetworkRange_BeforeCreate(t *testing.T) {
	nr := &NetworkRange{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		Name:          "Internal Network",
		CIDR:          "192.168.1.0/24",
		NetworkType:   "internal",
	}
	
	db := &gorm.DB{}
	err := nr.BeforeCreate(db)
	
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, nr.ID)
}

func TestNetworkRange_Structure(t *testing.T) {
	envID := uuid.New()
	tenantID := uuid.New()
	vlan := 100
	
	networkRange := NetworkRange{
		EnvironmentID: envID,
		TenantID:      tenantID,
		Name:          "Internal Network",
		CIDR:          "10.0.0.0/24",
		NetworkType:   "internal",
		VLAN:          &vlan,
		Description:   "Internal network",
		IsMonitored:   true,
	}
	
	assert.Equal(t, envID, networkRange.EnvironmentID)
	assert.Equal(t, tenantID, networkRange.TenantID)
	assert.Equal(t, "10.0.0.0/24", networkRange.CIDR)
	assert.Equal(t, "Internal network", networkRange.Description)
	assert.Equal(t, "internal", networkRange.NetworkType)
	assert.NotNil(t, networkRange.VLAN)
	assert.Equal(t, 100, *networkRange.VLAN)
	assert.True(t, networkRange.IsMonitored)
}

func TestPublicIP_Structure(t *testing.T) {
	publicIP := PublicIP{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		IPAddress:     "203.0.113.1",
		IPType:        "ipv4",
		Purpose:       "web",
		Provider:      "AWS",
		Region:        "us-east-1",
		IsActive:      true,
	}
	
	assert.Equal(t, "203.0.113.1", publicIP.IPAddress)
	assert.Equal(t, "ipv4", publicIP.IPType)
	assert.Equal(t, "web", publicIP.Purpose)
	assert.Equal(t, "AWS", publicIP.Provider)
	assert.Equal(t, "us-east-1", publicIP.Region)
	assert.True(t, publicIP.IsActive)
}

func TestEgressIP_Structure(t *testing.T) {
	egressIP := EgressIP{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		IPAddress:     "203.0.113.2",
		IPType:        "ipv4",
		Purpose:       "api_calls",
		Provider:      "NAT Gateway",
		IsActive:      true,
	}
	
	assert.Equal(t, "203.0.113.2", egressIP.IPAddress)
	assert.Equal(t, "ipv4", egressIP.IPType)
	assert.Equal(t, "api_calls", egressIP.Purpose)
	assert.Equal(t, "NAT Gateway", egressIP.Provider)
	assert.True(t, egressIP.IsActive)
}

func TestDomain_Structure(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	
	domain := Domain{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		DomainName:    "example.com",
		DomainType:    "primary",
		Purpose:       "website",
		Registrar:     "GoDaddy",
		DNSProvider:   "Cloudflare",
		IsActive:      true,
		ExpiresAt:     &expiresAt,
	}
	
	assert.Equal(t, "example.com", domain.DomainName)
	assert.Equal(t, "primary", domain.DomainType)
	assert.Equal(t, "website", domain.Purpose)
	assert.Equal(t, "GoDaddy", domain.Registrar)
	assert.Equal(t, "Cloudflare", domain.DNSProvider)
	assert.True(t, domain.IsActive)
	assert.NotNil(t, domain.ExpiresAt)
}

func TestInfrastructureIP_Structure(t *testing.T) {
	port := 443
	
	infraIP := InfrastructureIP{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		IPAddress:     "10.0.1.10",
		ServiceType:   InfrastructureTypeDNS,
		Hostname:      "dns-server-1",
		Port:          &port,
		Description:   "Primary DNS server",
		IsActive:      true,
		IsCritical:    true,
	}
	
	assert.Equal(t, "10.0.1.10", infraIP.IPAddress)
	assert.Equal(t, "dns-server-1", infraIP.Hostname)
	assert.Equal(t, InfrastructureTypeDNS, infraIP.ServiceType)
	assert.NotNil(t, infraIP.Port)
	assert.Equal(t, 443, *infraIP.Port)
	assert.Equal(t, "Primary DNS server", infraIP.Description)
	assert.True(t, infraIP.IsActive)
	assert.True(t, infraIP.IsCritical)
}

func TestNamingConvention_Structure(t *testing.T) {
	nc := NamingConvention{
		EnvironmentID: uuid.New(),
		TenantID:      uuid.New(),
		Name:          "Server Naming",
		Pattern:       "{location}-{env}-{service}-{number}",
		ResourceType:  "server",
		Description:   "Standard server naming convention",
		IsActive:      true,
	}
	
	assert.Equal(t, "Server Naming", nc.Name)
	assert.Equal(t, "{location}-{env}-{service}-{number}", nc.Pattern)
	assert.Equal(t, "server", nc.ResourceType)
	assert.Equal(t, "Standard server naming convention", nc.Description)
	assert.True(t, nc.IsActive)
}

func TestTenantAccessGrant_Structure(t *testing.T) {
	envID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	grantedBy := uuid.New()
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	
	grant := TenantAccessGrant{
		EnvironmentID:     envID,
		TenantID:          tenantID,
		GrantedToUserID:   userID,
		GrantedToTenantID: tenantID,
		AccessLevel:       AccessLevelReadWrite,
		GrantedBy:         grantedBy,
		ExpiresAt:         &expiresAt,
		IsActive:          true,
	}
	
	assert.Equal(t, envID, grant.EnvironmentID)
	assert.Equal(t, tenantID, grant.TenantID)
	assert.Equal(t, userID, grant.GrantedToUserID)
	assert.Equal(t, AccessLevelReadWrite, grant.AccessLevel)
	assert.Equal(t, grantedBy, grant.GrantedBy)
	assert.NotNil(t, grant.ExpiresAt)
	assert.True(t, grant.IsActive)
}

func TestCreateTenantAccessGrantRequest_Structure(t *testing.T) {
	envID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	grantedBy := uuid.New()
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	
	req := CreateTenantAccessGrantRequest{
		EnvironmentID:     envID,
		GrantedToUserID:   userID,
		GrantedToTenantID: tenantID,
		AccessLevel:       AccessLevelRead,
		GrantedBy:         grantedBy,
		ExpiresAt:         &expiresAt,
	}
	
	assert.Equal(t, envID, req.EnvironmentID)
	assert.Equal(t, userID, req.GrantedToUserID)
	assert.Equal(t, tenantID, req.GrantedToTenantID)
	assert.Equal(t, AccessLevelRead, req.AccessLevel)
	assert.Equal(t, grantedBy, req.GrantedBy)
	assert.NotNil(t, req.ExpiresAt)
}

func TestInfrastructureTypeConstants(t *testing.T) {
	types := []InfrastructureType{
		InfrastructureTypeDHCP,
		InfrastructureTypeDNS,
		InfrastructureTypeNetworkScanner,
		InfrastructureTypeProxyServer,
		InfrastructureTypeVPNServer,
		InfrastructureTypeNTPServer,
		InfrastructureTypeSyslogServer,
		InfrastructureTypeSIEMCollector,
		InfrastructureTypeAntivirus,
		InfrastructureTypeBackupServer,
		InfrastructureTypeLoadBalancer,
		InfrastructureTypeFirewall,
	}
	
	for _, infraType := range types {
		assert.NotEmpty(t, infraType, "Infrastructure type should not be empty")
		assert.True(t, len(string(infraType)) > 0, "Infrastructure type should have content")
	}
}

func TestAccessLevelConstants(t *testing.T) {
	levels := []AccessLevel{
		AccessLevelRead,
		AccessLevelReadWrite,
		AccessLevelFullAccess,
	}
	
	for _, level := range levels {
		assert.NotEmpty(t, level, "Access level should not be empty")
		assert.True(t, len(string(level)) > 0, "Access level should have content")
	}
	
	// Test specific values
	assert.Equal(t, AccessLevel("read"), AccessLevelRead)
	assert.Equal(t, AccessLevel("read_write"), AccessLevelReadWrite)
	assert.Equal(t, AccessLevel("full_access"), AccessLevelFullAccess)
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		expectErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Invalid IP", "not.an.ip", true},
		{"Empty string", "", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPAddress(tt.ip)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr bool
	}{
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Invalid CIDR", "not.a.cidr/24", true},
		{"Missing prefix", "192.168.1.0", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDR(tt.cidr)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNetworkRange_IsIPInRange(t *testing.T) {
	nr := &NetworkRange{
		CIDR: "192.168.1.0/24",
	}
	
	tests := []struct {
		name        string
		ip          string
		expectInRange bool
		expectErr   bool
	}{
		{"IP in range", "192.168.1.100", true, false},
		{"IP not in range", "10.0.0.1", false, false},
		{"Invalid IP", "not.an.ip", false, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inRange, err := nr.IsIPInRange(tt.ip)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectInRange, inRange)
			}
		})
	}
}

func TestGetIPType(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"IPv4", "192.168.1.1", "ipv4"},
		{"IPv6", "2001:db8::1", "ipv6"},
		{"Invalid IP", "not.an.ip", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetIPType(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Private IPv4", "192.168.1.1", true},
		{"Public IPv4", "8.8.8.8", false},
		{"Private IPv6", "fd00::1", true},
		{"Invalid IP", "not.an.ip", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		expectErr bool
	}{
		{"Valid domain", "example.com", false},
		{"Valid subdomain", "api.example.com", false},
		{"Empty domain", "", true},
		{"Single label", "localhost", true},
		{"Too long domain", string(make([]byte, 254)), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainName(tt.domain)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSIEMEnrichmentData_Structure(t *testing.T) {
	enrichment := SIEMEnrichmentData{
		TenantID:      uuid.New(),
		NetworkRanges: []NetworkRange{{CIDR: "192.168.1.0/24"}},
		PublicIPs:     []PublicIP{{IPAddress: "203.0.113.1"}},
		LastUpdated:   time.Now(),
	}
	
	assert.NotEqual(t, uuid.Nil, enrichment.TenantID)
	assert.Len(t, enrichment.NetworkRanges, 1)
	assert.Len(t, enrichment.PublicIPs, 1)
	assert.False(t, enrichment.LastUpdated.IsZero())
}

func TestEnrichmentLookupResult_Structure(t *testing.T) {
	result := EnrichmentLookupResult{
		Type:            "ip",
		Value:           "192.168.1.1",
		TenantID:        uuid.New(),
		EnvironmentID:   uuid.New(),
		EnvironmentName: "production",
		Classification:  "internal",
		Purpose:         "database",
		IsPrivate:       true,
		IsCritical:      true,
		Tags:            map[string]interface{}{"team": "backend"},
		AdditionalInfo:  map[string]interface{}{"service": "postgresql"},
	}
	
	assert.Equal(t, "ip", result.Type)
	assert.Equal(t, "192.168.1.1", result.Value)
	assert.Equal(t, "production", result.EnvironmentName)
	assert.Equal(t, "internal", result.Classification)
	assert.Equal(t, "database", result.Purpose)
	assert.True(t, result.IsPrivate)
	assert.True(t, result.IsCritical)
	assert.NotEmpty(t, result.Tags)
	assert.NotEmpty(t, result.AdditionalInfo)
}