package constants

import "time"

const (
	DefaultProvider   = "keycloak"
	DefaultMSPRealm   = "master"
	BearerTokenPrefix = "Bearer "
	TokenExpiryBuffer = 60 * time.Second

	DefaultTimeout    = 30 * time.Second
	HTTPClientTimeout = 30 * time.Second
	ValidationTimeout = 60 * time.Second
	InitTimeout       = 120 * time.Second
	FullInitTimeout   = 300 * time.Second
	ShutdownTimeout   = 30 * time.Second

	DefaultPageSize = 20
	MaxPageSize     = 100
	MinPageSize     = 1

	MinPasswordLength = 12
	MaxPasswordLength = 128

	MaxRequestSize    = 32 << 20
	MaxFileUploadSize = 10 << 20

	DefaultCacheTTL = 5 * time.Minute

	RoleMSPAdmin    = "msp-admin"
	RoleMSPPower    = "msp-power"
	RoleMSPBasic    = "msp-basic"
	RoleTenantAdmin = "tenant-admin"
	RoleTenantUser  = "tenant-user"

	TenantIDKey = "tenant_id"

	// CalVer format: YYYY-MM-DD (Calendar Versioning)
	// New version for each breaking change release
	APIVersion  = "2025-08-01"
	APIBasePath = "/api/" + APIVersion

	PathHealth                 = "/health"
	PathHealthKeycloak         = "/health/keycloak"
	PathSwagger                = "/swagger/"
	PathAuth                   = "/auth"
	PathAuthCallback           = "/callback"
	PathAuthProviders          = "/providers"
	PathAuthProvidersWellKnown = "/providers/:provider/.well-known"
	PathAuthLogin              = "/login"
	PathAuthValidate           = "/validate"
	PathAuthLogout             = "/logout"
	PathAuthUserInfo           = "/userinfo"
	PathAuthServiceToken       = "/service-token"
	PathAuthServiceValidate    = "/service-validate"

	PathAdmin             = "/admin"
	PathAdminTenants      = APIBasePath + PathAdmin + "/tenants"
	PathAdminUsers        = APIBasePath + PathAdmin + "/users"
	PathAdminRoles        = APIBasePath + PathAdmin + "/roles"
	PathAdminSSO          = APIBasePath + PathAdmin + "/sso"
	PathAdminAudit        = APIBasePath + PathAdmin + "/audit"
	PathAdminEnvironments = APIBasePath + PathAdmin + "/environments"

	PathTenants                   = "/tenants"
	PathUsers                     = "/users"
	PathUsersID                   = "/users/:id"
	PathUsersBulkCreate           = "/users/bulk-create"
	PathUsersImportCSV            = "/users/import-csv"
	PathRoles                     = "/roles"
	PathRolesID                   = "/roles/:id"
	PathSSO                       = "/sso"
	PathSSOProviders              = "/sso/providers"
	PathSSOProvidersID            = "/sso/providers/:id"
	PathAudit                     = "/audit"
	PathAuditID                   = "/audit/:id"
	PathAuditExport               = "/audit/export"
	PathEnvironments              = "/environments"
	PathEnvironmentsID            = "/environments/:id"
	PathEnvironmentAccess         = "/environments/access"
	PathEnvironmentAccessGrant    = "/environments/access/:grant_id"
	PathEnvironmentSecurityData   = "/environments/security-data"
	PathEnvironmentNetworks       = "/environments/networks"
	PathEnvironmentInfrastructure = "/environments/infrastructure"

	PathAdminTenantsID        = "/tenants/:id"
	PathAdminTenantsProvision = "/tenants/:id/provision"
	PathAdminUsersID          = "/users/:id"
	PathAdminRolesID          = "/roles/:id"

	EndpointAuthProviders    = APIBasePath + PathAuth + PathAuthProviders
	EndpointAuthValidate     = APIBasePath + PathAuth + PathAuthValidate
	EndpointAuthServiceToken = APIBasePath + PathAuth + PathAuthServiceToken
	EndpointAuthUserInfo     = APIBasePath + PathAuth + PathAuthUserInfo
	EndpointAdminTenants     = APIBasePath + PathAdmin + PathTenants
	EndpointAdminUsers       = APIBasePath + PathAdmin + PathUsers
	EndpointAdminRoles       = APIBasePath + PathAdmin + PathRoles
)
