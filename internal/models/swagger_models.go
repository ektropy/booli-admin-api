package models

import (
	"time"

	"github.com/google/uuid"
)

// swagger:model TenantEnvironmentSwagger
type TenantEnvironmentSwagger struct {
	ID          uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm string    `json:"tenant_realm" example:"client-tenant"`
	Name        string    `json:"name" example:"Production Environment"`
	Description string    `json:"description" example:"Main production environment"`
	Environment string    `json:"environment" example:"production"`
	IsActive    bool      `json:"is_active" example:"true"`
	CreatedAt   time.Time `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt   time.Time `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" example:"null"`

	NetworkRanges     []NetworkRangeSwagger     `json:"network_ranges,omitempty"`
	PublicIPs         []PublicIPSwagger         `json:"public_ips,omitempty"`
	EgressIPs         []EgressIPSwagger         `json:"egress_ips,omitempty"`
	Domains           []DomainSwagger           `json:"domains,omitempty"`
	NamingConventions []NamingConventionSwagger `json:"naming_conventions,omitempty"`
	InfrastructureIPs []InfrastructureIPSwagger `json:"infrastructure_ips,omitempty"`
	AccessGrants      []TenantAccessGrantSwagger `json:"access_grants,omitempty"`
}

// swagger:model NetworkRangeSwagger
type NetworkRangeSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440001"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	Name          string                 `json:"name" example:"Internal Network"`
	CIDR          string                 `json:"cidr" example:"10.0.0.0/16"`
	NetworkType   string                 `json:"network_type" example:"internal"`
	VLAN          *int                   `json:"vlan,omitempty" example:"100"`
	Description   string                 `json:"description" example:"Internal network range"`
	IsMonitored   bool                   `json:"is_monitored" example:"true"`
	Tags          map[string]interface{} `json:"tags"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model PublicIPSwagger
type PublicIPSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440002"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	IPAddress     string                 `json:"ip_address" example:"203.0.113.1"`
	IPType        string                 `json:"ip_type" example:"ipv4"`
	Purpose       string                 `json:"purpose" example:"web"`
	Provider      string                 `json:"provider" example:"aws"`
	Region        string                 `json:"region" example:"us-east-1"`
	IsActive      bool                   `json:"is_active" example:"true"`
	Tags          map[string]interface{} `json:"tags"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model EgressIPSwagger
type EgressIPSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440003"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	IPAddress     string                 `json:"ip_address" example:"203.0.113.10"`
	IPType        string                 `json:"ip_type" example:"ipv4"`
	Purpose       string                 `json:"purpose" example:"api_calls"`
	Provider      string                 `json:"provider" example:"nat_gateway"`
	IsActive      bool                   `json:"is_active" example:"true"`
	Tags          map[string]interface{} `json:"tags"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model DomainSwagger
type DomainSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440004"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	DomainName    string                 `json:"domain_name" example:"example.com"`
	DomainType    string                 `json:"domain_type" example:"primary"`
	Purpose       string                 `json:"purpose" example:"website"`
	Registrar     string                 `json:"registrar" example:"godaddy"`
	DNSProvider   string                 `json:"dns_provider" example:"cloudflare"`
	IsActive      bool                   `json:"is_active" example:"true"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty" example:"2025-12-31T23:59:59Z"`
	Tags          map[string]interface{} `json:"tags"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model NamingConventionSwagger
type NamingConventionSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440005"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	Name          string                 `json:"name" example:"server-naming"`
	Pattern       string                 `json:"pattern" example:"{env}-{service}-{number}"`
	ResourceType  string                 `json:"resource_type" example:"server"`
	Examples      map[string]interface{} `json:"examples"`
	Description   string                 `json:"description" example:"Standard server naming convention"`
	IsActive      bool                   `json:"is_active" example:"true"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model InfrastructureIPSwagger
type InfrastructureIPSwagger struct {
	ID            uuid.UUID              `json:"id" example:"550e8400-e29b-41d4-a716-446655440006"`
	EnvironmentID uuid.UUID              `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm   string                 `json:"tenant_realm" example:"client-tenant"`
	IPAddress     string                 `json:"ip_address" example:"10.0.1.10"`
	ServiceType   string                 `json:"service_type" example:"dns"`
	Hostname      string                 `json:"hostname" example:"dns1.internal.example.com"`
	Port          *int                   `json:"port,omitempty" example:"53"`
	Description   string                 `json:"description" example:"Primary DNS server"`
	IsActive      bool                   `json:"is_active" example:"true"`
	IsCritical    bool                   `json:"is_critical" example:"true"`
	Tags          map[string]interface{} `json:"tags"`
	CreatedAt     time.Time              `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt     time.Time              `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt     *time.Time             `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model TenantAccessGrantSwagger
type TenantAccessGrantSwagger struct {
	ID                  uuid.UUID  `json:"id" example:"550e8400-e29b-41d4-a716-446655440007"`
	EnvironmentID       uuid.UUID  `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantRealm         string     `json:"tenant_realm" example:"client-tenant"`
	GrantedToUserID     uuid.UUID  `json:"granted_to_user_id" example:"550e8400-e29b-41d4-a716-446655440008"`
	GrantedToTenantRealm string    `json:"granted_to_tenant_realm" example:"master"`
	AccessLevel         string     `json:"access_level" example:"read"`
	GrantedBy           uuid.UUID  `json:"granted_by" example:"550e8400-e29b-41d4-a716-446655440009"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty" example:"2025-12-31T23:59:59Z"`
	IsActive            bool       `json:"is_active" example:"true"`
	CreatedAt           time.Time  `json:"created_at" example:"2024-01-01T12:00:00Z"`
	UpdatedAt           time.Time  `json:"updated_at" example:"2024-01-01T12:00:00Z"`
	DeletedAt           *time.Time `json:"deleted_at,omitempty" example:"null"`
}

// swagger:model CreateTenantEnvironmentRequestSwagger
type CreateTenantEnvironmentRequestSwagger struct {
	TenantRealm       string                        `json:"tenant_realm,omitempty" example:"client-tenant"`
	TenantName        string                        `json:"tenant_name,omitempty" example:"Acme Corp"`
	TenantDomain      string                        `json:"tenant_domain,omitempty" example:"acme.com"`
	Name              string                        `json:"name" example:"Production Environment"`
	Description       string                        `json:"description,omitempty" example:"Main production environment"`
	Environment       string                        `json:"environment,omitempty" example:"production"`
	NetworkRanges     []NetworkRangeSwagger         `json:"network_ranges,omitempty"`
	PublicIPs         []PublicIPSwagger             `json:"public_ips,omitempty"`
	EgressIPs         []EgressIPSwagger             `json:"egress_ips,omitempty"`
	Domains           []DomainSwagger               `json:"domains,omitempty"`
	NamingConventions []NamingConventionSwagger     `json:"naming_conventions,omitempty"`
	InfrastructureIPs []InfrastructureIPSwagger     `json:"infrastructure_ips,omitempty"`
}

// swagger:model UpdateTenantEnvironmentRequestSwagger
type UpdateTenantEnvironmentRequestSwagger struct {
	Name        *string `json:"name,omitempty" example:"Production Environment Updated"`
	Description *string `json:"description,omitempty" example:"Updated main production environment"`
	Environment *string `json:"environment,omitempty" example:"production"`
	IsActive    *bool   `json:"is_active,omitempty" example:"true"`
}

// swagger:model TenantEnvironmentListResponseSwagger
type TenantEnvironmentListResponseSwagger struct {
	Environments []TenantEnvironmentSwagger `json:"environments"`
	Total        int64                       `json:"total" example:"25"`
	Page         int                         `json:"page" example:"1"`
	PageSize     int                         `json:"page_size" example:"20"`
	TotalPages   int                         `json:"total_pages" example:"2"`
}

// swagger:model CreateTenantAccessGrantRequestSwagger
type CreateTenantAccessGrantRequestSwagger struct {
	EnvironmentID         uuid.UUID  `json:"environment_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	GrantedToUserID       uuid.UUID  `json:"granted_to_user_id" example:"550e8400-e29b-41d4-a716-446655440008"`
	GrantedToTenantRealm  string     `json:"granted_to_tenant_realm" example:"master"`
	AccessLevel           string     `json:"access_level" example:"read" enums:"read,read_write,full_access"`
	GrantedBy             uuid.UUID  `json:"granted_by" example:"550e8400-e29b-41d4-a716-446655440009"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty" example:"2025-12-31T23:59:59Z"`
}

// swagger:model SIEMEnrichmentDataSwagger
type SIEMEnrichmentDataSwagger struct {
	TenantRealm       string                        `json:"tenant_realm" example:"client-tenant"`
	NetworkRanges     []NetworkRangeSwagger         `json:"network_ranges"`
	PublicIPs         []PublicIPSwagger             `json:"public_ips"`
	EgressIPs         []EgressIPSwagger             `json:"egress_ips"`
	Domains           []DomainSwagger               `json:"domains"`
	InfrastructureIPs []InfrastructureIPSwagger     `json:"infrastructure_ips"`
	LastUpdated       time.Time                     `json:"last_updated" example:"2024-01-01T12:00:00Z"`
}

// swagger:model ErrorResponseSwagger
type ErrorResponseSwagger struct {
	Error     ErrorDetailSwagger `json:"error"`
	Status    int                `json:"status" example:"400"`
	Path      string             `json:"path" example:"/api/v1/environments"`
	Timestamp string             `json:"timestamp" example:"2024-01-01T12:00:00Z"`
	RequestID string             `json:"request_id,omitempty" example:"req-123456789"`
}

// swagger:model ErrorDetailSwagger
type ErrorDetailSwagger struct {
	Code    string `json:"code" example:"BAD_REQUEST"`
	Message string `json:"message" example:"Invalid request body"`
	Details string `json:"details,omitempty" example:"Field validation error"`
}