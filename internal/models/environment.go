package models

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type TenantEnvironment struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID    uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name        string         `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Description string         `gorm:"size:1000" json:"description"`
	Environment string         `gorm:"size:100" json:"environment"` // production, staging, development, etc.
	IsActive    bool           `gorm:"default:true" json:"is_active"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	Tenant            Tenant              `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
	NetworkRanges     []NetworkRange      `gorm:"foreignKey:EnvironmentID" json:"network_ranges,omitempty"`
	PublicIPs         []PublicIP          `gorm:"foreignKey:EnvironmentID" json:"public_ips,omitempty"`
	EgressIPs         []EgressIP          `gorm:"foreignKey:EnvironmentID" json:"egress_ips,omitempty"`
	Domains           []Domain            `gorm:"foreignKey:EnvironmentID" json:"domains,omitempty"`
	NamingConventions []NamingConvention  `gorm:"foreignKey:EnvironmentID" json:"naming_conventions,omitempty"`
	InfrastructureIPs []InfrastructureIP  `gorm:"foreignKey:EnvironmentID" json:"infrastructure_ips,omitempty"`
	AccessGrants      []TenantAccessGrant `gorm:"foreignKey:EnvironmentID" json:"access_grants,omitempty"`
}

type NetworkRange struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name          string         `gorm:"not null;size:255" json:"name"`
	CIDR          string         `gorm:"not null;size:50" json:"cidr" validate:"required,cidr"`
	NetworkType   string         `gorm:"size:50" json:"network_type"` // internal, dmz, management, guest, etc.
	VLAN          *int           `json:"vlan,omitempty"`
	Description   string         `gorm:"size:500" json:"description"`
	IsMonitored   bool           `gorm:"default:true" json:"is_monitored"`
	Tags          datatypes.JSON `gorm:"type:jsonb" json:"tags"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type PublicIP struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	IPAddress     string         `gorm:"not null;size:45" json:"ip_address" validate:"required,ip"`
	IPType        string         `gorm:"size:20" json:"ip_type"`   // ipv4, ipv6
	Purpose       string         `gorm:"size:100" json:"purpose"`  // web, mail, dns, vpn, etc.
	Provider      string         `gorm:"size:100" json:"provider"` // AWS, Azure, GCP, ISP name, etc.
	Region        string         `gorm:"size:100" json:"region"`
	IsActive      bool           `gorm:"default:true" json:"is_active"`
	Tags          datatypes.JSON `gorm:"type:jsonb" json:"tags"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type EgressIP struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	IPAddress     string         `gorm:"not null;size:45" json:"ip_address" validate:"required,ip"`
	IPType        string         `gorm:"size:20" json:"ip_type"`   // ipv4, ipv6
	Purpose       string         `gorm:"size:100" json:"purpose"`  // general, api_calls, email, etc.
	Provider      string         `gorm:"size:100" json:"provider"` // NAT Gateway, Proxy, VPN, etc.
	IsActive      bool           `gorm:"default:true" json:"is_active"`
	Tags          datatypes.JSON `gorm:"type:jsonb" json:"tags"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type Domain struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	DomainName    string         `gorm:"not null;size:255" json:"domain_name" validate:"required,fqdn"`
	DomainType    string         `gorm:"size:50" json:"domain_type"` // primary, subdomain, wildcard
	Purpose       string         `gorm:"size:100" json:"purpose"`    // website, email, api, internal, etc.
	Registrar     string         `gorm:"size:100" json:"registrar"`
	DNSProvider   string         `gorm:"size:100" json:"dns_provider"`
	IsActive      bool           `gorm:"default:true" json:"is_active"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	Tags          datatypes.JSON `gorm:"type:jsonb" json:"tags"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type NamingConvention struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name          string         `gorm:"not null;size:255" json:"name"`
	Pattern       string         `gorm:"not null;size:500" json:"pattern"` // e.g., "{location}-{env}-{service}-{number}"
	ResourceType  string         `gorm:"size:100" json:"resource_type"`    // server, vm, container, service, etc.
	Examples      datatypes.JSON `gorm:"type:jsonb" json:"examples"`
	Description   string         `gorm:"size:500" json:"description"`
	IsActive      bool           `gorm:"default:true" json:"is_active"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type InfrastructureIP struct {
	ID            uuid.UUID          `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID uuid.UUID          `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID      uuid.UUID          `gorm:"type:uuid;not null;index" json:"tenant_id"`
	IPAddress     string             `gorm:"not null;size:45" json:"ip_address" validate:"required,ip"`
	ServiceType   InfrastructureType `gorm:"not null;size:50" json:"service_type"`
	Hostname      string             `gorm:"size:255" json:"hostname"`
	Port          *int               `json:"port,omitempty"`
	Description   string             `gorm:"size:500" json:"description"`
	IsActive      bool               `gorm:"default:true" json:"is_active"`
	IsCritical    bool               `gorm:"default:false" json:"is_critical"`
	Tags          datatypes.JSON     `gorm:"type:jsonb" json:"tags"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	DeletedAt     gorm.DeletedAt     `gorm:"index" json:"deleted_at,omitempty"`
}

type TenantAccessGrant struct {
	ID                uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	EnvironmentID     uuid.UUID      `gorm:"type:uuid;not null;index" json:"environment_id"`
	TenantID          uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenant_id"` // Target tenant
	GrantedToUserID   uuid.UUID      `gorm:"type:uuid;not null;index" json:"granted_to_user_id"`
	GrantedToTenantID uuid.UUID      `gorm:"type:uuid;not null;index" json:"granted_to_tenant_id"` // MSP tenant
	AccessLevel       AccessLevel    `gorm:"not null;size:50" json:"access_level"`
	GrantedBy         uuid.UUID      `gorm:"type:uuid;not null" json:"granted_by"`
	ExpiresAt         *time.Time     `json:"expires_at,omitempty"`
	IsActive          bool           `gorm:"default:true" json:"is_active"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	GrantedToUser   User   `gorm:"-" json:"granted_to_user,omitempty"`
	GrantedToTenant Tenant `gorm:"foreignKey:GrantedToTenantID" json:"granted_to_tenant,omitempty"`
}

type InfrastructureType string

const (
	InfrastructureTypeDHCP           InfrastructureType = "dhcp"
	InfrastructureTypeDNS            InfrastructureType = "dns"
	InfrastructureTypeNetworkScanner InfrastructureType = "network_scanner"
	InfrastructureTypeProxyServer    InfrastructureType = "proxy_server"
	InfrastructureTypeVPNServer      InfrastructureType = "vpn_server"
	InfrastructureTypeNTPServer      InfrastructureType = "ntp_server"
	InfrastructureTypeSyslogServer   InfrastructureType = "syslog_server"
	InfrastructureTypeSIEMCollector  InfrastructureType = "siem_collector"
	InfrastructureTypeAntivirus      InfrastructureType = "antivirus"
	InfrastructureTypeBackupServer   InfrastructureType = "backup_server"
	InfrastructureTypeLoadBalancer   InfrastructureType = "load_balancer"
	InfrastructureTypeFirewall       InfrastructureType = "firewall"
)

type AccessLevel string

const (
	AccessLevelRead       AccessLevel = "read"
	AccessLevelReadWrite  AccessLevel = "read_write"
	AccessLevelFullAccess AccessLevel = "full_access"
)

type NetworkTags struct {
	BusinessUnit string            `json:"business_unit,omitempty"`
	CostCenter   string            `json:"cost_center,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	Criticality  string            `json:"criticality,omitempty"`
	CustomTags   map[string]string `json:"custom_tags,omitempty"`
}

type IPTags struct {
	BusinessUnit string            `json:"business_unit,omitempty"`
	CostCenter   string            `json:"cost_center,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	Service      string            `json:"service,omitempty"`
	CustomTags   map[string]string `json:"custom_tags,omitempty"`
}

type DomainTags struct {
	BusinessUnit string            `json:"business_unit,omitempty"`
	CostCenter   string            `json:"cost_center,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	SSL          bool              `json:"ssl,omitempty"`
	CDN          string            `json:"cdn,omitempty"`
	CustomTags   map[string]string `json:"custom_tags,omitempty"`
}

type InfrastructureTags struct {
	BusinessUnit string            `json:"business_unit,omitempty"`
	CostCenter   string            `json:"cost_center,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	Version      string            `json:"version,omitempty"`
	Vendor       string            `json:"vendor,omitempty"`
	CustomTags   map[string]string `json:"custom_tags,omitempty"`
}

type NamingExamples struct {
	Valid   []string `json:"valid"`
	Invalid []string `json:"invalid,omitempty"`
}

func (te *TenantEnvironment) BeforeCreate(tx *gorm.DB) error {
	if te.ID == uuid.Nil {
		te.ID = uuid.New()
	}
	return nil
}

func (nr *NetworkRange) BeforeCreate(tx *gorm.DB) error {
	if nr.ID == uuid.Nil {
		nr.ID = uuid.New()
	}
	return nil
}

func (pi *PublicIP) BeforeCreate(tx *gorm.DB) error {
	if pi.ID == uuid.Nil {
		pi.ID = uuid.New()
	}
	return nil
}

func (ei *EgressIP) BeforeCreate(tx *gorm.DB) error {
	if ei.ID == uuid.Nil {
		ei.ID = uuid.New()
	}
	return nil
}

func (d *Domain) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

func (nc *NamingConvention) BeforeCreate(tx *gorm.DB) error {
	if nc.ID == uuid.Nil {
		nc.ID = uuid.New()
	}
	return nil
}

func (iip *InfrastructureIP) BeforeCreate(tx *gorm.DB) error {
	if iip.ID == uuid.Nil {
		iip.ID = uuid.New()
	}
	return nil
}

func (tag *TenantAccessGrant) BeforeCreate(tx *gorm.DB) error {
	if tag.ID == uuid.Nil {
		tag.ID = uuid.New()
	}
	return nil
}

func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

func (nr *NetworkRange) IsIPInRange(ip string) (bool, error) {
	if err := ValidateIPAddress(ip); err != nil {
		return false, err
	}

	if err := ValidateCIDR(nr.CIDR); err != nil {
		return false, err
	}

	_, network, err := net.ParseCIDR(nr.CIDR)
	if err != nil {
		return false, err
	}

	return network.Contains(net.ParseIP(ip)), nil
}

func GetIPType(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	if parsedIP.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	if parsedIP.To4() != nil {
		return parsedIP.IsPrivate()
	}

	return parsedIP.IsPrivate()
}

func ValidateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain name cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain name too long")
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid domain format")
	}

	return nil
}

type CreateTenantEnvironmentRequest struct {
	TenantID          uuid.UUID          `json:"tenant_id,omitempty"`
	TenantName        string             `json:"tenant_name,omitempty"`
	TenantDomain      string             `json:"tenant_domain,omitempty"`
	Name              string             `json:"name" validate:"required,min=1,max=255"`
	Description       string             `json:"description,omitempty"`
	Environment       string             `json:"environment,omitempty"` // production, staging, development, etc.
	NetworkRanges     []NetworkRange     `json:"network_ranges,omitempty"`
	PublicIPs         []PublicIP         `json:"public_ips,omitempty"`
	EgressIPs         []EgressIP         `json:"egress_ips,omitempty"`
	Domains           []Domain           `json:"domains,omitempty"`
	NamingConventions []NamingConvention `json:"naming_conventions,omitempty"`
	InfrastructureIPs []InfrastructureIP `json:"infrastructure_ips,omitempty"`
}

type UpdateTenantEnvironmentRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string `json:"description,omitempty"`
	Environment *string `json:"environment,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

type TenantEnvironmentListResponse struct {
	Environments []TenantEnvironment `json:"environments"`
	Total        int64               `json:"total"`
	Page         int                 `json:"page"`
	PageSize     int                 `json:"page_size"`
	TotalPages   int                 `json:"total_pages"`
}

type CreateTenantAccessGrantRequest struct {
	EnvironmentID     uuid.UUID   `json:"environment_id" validate:"required"`
	GrantedToUserID   uuid.UUID   `json:"granted_to_user_id" validate:"required"`
	GrantedToTenantID uuid.UUID   `json:"granted_to_tenant_id" validate:"required"`
	AccessLevel       AccessLevel `json:"access_level" validate:"required,oneof=read read_write full_access"`
	GrantedBy         uuid.UUID   `json:"granted_by" validate:"required"`
	ExpiresAt         *time.Time  `json:"expires_at,omitempty"`
}

type SIEMEnrichmentData struct {
	TenantID          uuid.UUID          `json:"tenant_id"`
	NetworkRanges     []NetworkRange     `json:"network_ranges"`
	PublicIPs         []PublicIP         `json:"public_ips"`
	EgressIPs         []EgressIP         `json:"egress_ips"`
	Domains           []Domain           `json:"domains"`
	InfrastructureIPs []InfrastructureIP `json:"infrastructure_ips"`
	LastUpdated       time.Time          `json:"last_updated"`
}

type EnrichmentLookupResult struct {
	Type            string                 `json:"type"` // ip, domain, network
	Value           string                 `json:"value"`
	TenantID        uuid.UUID              `json:"tenant_id"`
	EnvironmentID   uuid.UUID              `json:"environment_id"`
	EnvironmentName string                 `json:"environment_name"`
	Classification  string                 `json:"classification"` // internal, external, public, egress, infrastructure
	Purpose         string                 `json:"purpose,omitempty"`
	IsPrivate       bool                   `json:"is_private,omitempty"`
	IsCritical      bool                   `json:"is_critical,omitempty"`
	Tags            map[string]interface{} `json:"tags,omitempty"`
	AdditionalInfo  map[string]interface{} `json:"additional_info,omitempty"`
}
