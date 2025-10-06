package initialization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/services"
	"go.uber.org/zap"
)

type RealmConfig struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Enabled     bool   `json:"enabled"`
}

type ClientConfig struct {
	RealmName                 string   `json:"realm_name"`
	ClientID                  string   `json:"client_id"`
	Secret                    string   `json:"secret"`
	RedirectURIs              []string `json:"redirect_uris"`
	WebOrigins                []string `json:"web_origins"`
	StandardFlowEnabled       bool     `json:"standard_flow_enabled"`
	ServiceAccountsEnabled    bool     `json:"service_accounts_enabled"`
	DirectAccessGrantsEnabled bool     `json:"direct_access_grants_enabled"`
	ImplicitFlowEnabled       bool     `json:"implicit_flow_enabled"`
	PublicClient              bool     `json:"public_client"`
	APIAudience               string   `json:"api_audience,omitempty"`
}

type RoleConfig struct {
	RealmName   string `json:"realm_name"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type OIDCProviderConfig struct {
	Name         string `json:"name"`
	RealmName    string `json:"realm_name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CallbackURL  string `json:"callback_url"`
}

type UserConfig struct {
	RealmName string   `json:"realm_name"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Roles     []string `json:"roles"`
	Enabled   bool     `json:"enabled"`
	Temporary bool     `json:"temporary"`
}

type InitializationConfig struct {
	Realms        []RealmConfig        `json:"realms"`
	Clients       []ClientConfig       `json:"clients"`
	Roles         []RoleConfig         `json:"roles"`
	Users         []UserConfig         `json:"users"`
	OIDCProviders []OIDCProviderConfig `json:"oidc_providers"`
}

type KeycloakInitializer struct {
	keycloakAdmin     *keycloak.AdminClient
	oidcService       *auth.OIDCService
	config            *config.Config
	logger            *zap.Logger
	permissionService *services.PermissionService
}

func NewKeycloakInitializer(keycloakAdmin *keycloak.AdminClient, oidcService *auth.OIDCService, cfg *config.Config, logger *zap.Logger) *KeycloakInitializer {
	permissionService := services.NewPermissionService(keycloakAdmin, logger)
	return &KeycloakInitializer{
		keycloakAdmin:     keycloakAdmin,
		oidcService:       oidcService,
		config:            cfg,
		logger:            logger,
		permissionService: permissionService,
	}
}

func (k *KeycloakInitializer) Initialize(ctx context.Context, initConfig *InitializationConfig) error {
	k.logger.Info("Starting Keycloak initialization",
		zap.Int("realms", len(initConfig.Realms)),
		zap.Int("clients", len(initConfig.Clients)),
		zap.Int("roles", len(initConfig.Roles)),
		zap.Int("users", len(initConfig.Users)),
		zap.Int("providers", len(initConfig.OIDCProviders)))

	if err := k.waitForKeycloak(ctx, 20*time.Second); err != nil {
		return fmt.Errorf("Keycloak not ready: %w", err)
	}

	for _, realm := range initConfig.Realms {
		if err := k.initializeRealm(ctx, realm); err != nil {
			k.logger.Error("Failed to initialize realm", zap.String("realm", realm.Name), zap.Error(err))
			return err
		}
	}

	for _, client := range initConfig.Clients {
		if err := k.initializeClient(ctx, client); err != nil {
			k.logger.Error("Failed to initialize client",
				zap.String("realm", client.RealmName),
				zap.String("client", client.ClientID),
				zap.Error(err))
			return err
		}
	}

	for _, role := range initConfig.Roles {
		if err := k.initializeRole(ctx, role); err != nil {
			k.logger.Error("Failed to initialize role",
				zap.String("realm", role.RealmName),
				zap.String("role", role.Name),
				zap.Error(err))
			return err
		}
	}

	for _, user := range initConfig.Users {
		if err := k.initializeUser(ctx, user); err != nil {
			k.logger.Error("Failed to initialize user",
				zap.String("realm", user.RealmName),
				zap.String("user", user.Username),
				zap.Error(err))
			return err
		}
	}

	for _, realm := range initConfig.Realms {
		if err := k.setupRealmPermissions(ctx, realm.Name); err != nil {
			k.logger.Warn("Failed to setup FGAPv2 permissions", zap.String("realm", realm.Name), zap.Error(err))
		} else {
			k.logger.Info("FGAPv2 permissions setup completed", zap.String("realm", realm.Name))
		}
	}

	for _, provider := range initConfig.OIDCProviders {
		if err := k.registerOIDCProvider(ctx, provider); err != nil {
			k.logger.Error("Failed to register OIDC provider",
				zap.String("provider", provider.Name),
				zap.Error(err))
		}
	}

	k.logger.Info("Keycloak initialization completed successfully")
	return nil
}

func (k *KeycloakInitializer) ValidateConfiguration(ctx context.Context, initConfig *InitializationConfig) error {
	k.logger.Info("Validating Keycloak configuration")

	for _, realm := range initConfig.Realms {
		if err := k.validateRealm(ctx, realm.Name); err != nil {
			return fmt.Errorf("realm validation failed for %s: %w", realm.Name, err)
		}
	}

	for _, client := range initConfig.Clients {
		if err := k.validateClient(ctx, client.RealmName, client.ClientID); err != nil {
			return fmt.Errorf("client validation failed for %s/%s: %w", client.RealmName, client.ClientID, err)
		}
	}

	for _, role := range initConfig.Roles {
		if _, err := k.keycloakAdmin.GetRealmRole(ctx, role.RealmName, role.Name); err != nil {
			return fmt.Errorf("role validation failed for %s/%s: %w", role.RealmName, role.Name, err)
		}
	}

	for _, provider := range initConfig.OIDCProviders {
		if _, err := k.oidcService.GetProvider(provider.Name); err != nil {
			return fmt.Errorf("OIDC provider validation failed for %s: %w", provider.Name, err)
		}
	}

	k.logger.Info("Keycloak configuration validation completed successfully")
	return nil
}

func (k *KeycloakInitializer) waitForKeycloak(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	k.logger.Info("Waiting for Keycloak to be ready", zap.Duration("timeout", timeout))

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Keycloak")
		case <-ticker.C:
			if k.isKeycloakReady(ctx) {
				k.logger.Info("Keycloak is ready")
				return nil
			}
		}
	}
}

func (k *KeycloakInitializer) isKeycloakReady(ctx context.Context) bool {
	if k.config.Keycloak.URL == "" {
		k.logger.Error("Keycloak URL is not configured - application cannot start",
			zap.String("keycloak_url", k.config.Keycloak.URL),
			zap.String("required_env_var", "BOOLI_KEYCLOAK_URL"))
		os.Exit(1)
	}

	url := fmt.Sprintf("%s/realms/master/.well-known/openid-configuration", k.config.Keycloak.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		k.logger.Debug("Failed to create Keycloak readiness request", zap.Error(err), zap.String("url", url))
		return false
	}

	client := k.keycloakAdmin.GetHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		k.logger.Debug("Keycloak readiness check failed", zap.Error(err), zap.String("url", url))
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		k.logger.Debug("Keycloak readiness check returned non-200 status", zap.Int("status", resp.StatusCode), zap.String("url", url))
		return false
	}

	return true
}

func (k *KeycloakInitializer) TestAuthentication(ctx context.Context) error {
	return k.keycloakAdmin.TestAuthentication(ctx)
}

func (k *KeycloakInitializer) initializeRealm(ctx context.Context, realm RealmConfig) error {
	k.logger.Info("Initializing realm", zap.String("realm", realm.Name))

	realmExists := k.validateRealm(ctx, realm.Name) == nil
	if realmExists {
		k.logger.Info("Realm already exists", zap.String("realm", realm.Name))
	}

	realmRep := &keycloak.RealmRepresentation{
		Realm:                 realm.Name,
		Enabled:               realm.Enabled,
		DisplayName:           realm.DisplayName,
		LoginWithEmailAllowed: true,
		RegistrationAllowed:   false,
		ResetPasswordAllowed:  true,
		RememberMe:            true,
		VerifyEmail:           false,
	}

	if !realmExists {
		if err := k.keycloakAdmin.CreateRealm(ctx, realmRep); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("failed to create realm %s: %w", realm.Name, err)
			}
			k.logger.Info("Realm already exists", zap.String("realm", realm.Name))
		} else {
			k.logger.Info("Realm created successfully", zap.String("realm", realm.Name))
		}
	}

	if err := k.enableOrganizationsFeature(ctx, realm.Name); err != nil {
		k.logger.Warn("Failed to enable Organizations feature", zap.String("realm", realm.Name), zap.Error(err))
	} else {
		k.logger.Info("Organizations feature enabled", zap.String("realm", realm.Name))
	}

	return nil
}

func (k *KeycloakInitializer) enableOrganizationsFeature(ctx context.Context, realmName string) error {
	realmRep, err := k.keycloakAdmin.GetRealm(ctx, realmName)
	if err != nil {
		return fmt.Errorf("failed to get realm %s: %w", realmName, err)
	}

	if realmRep.Attributes == nil {
		realmRep.Attributes = make(map[string]string)
	}
	realmRep.Attributes["organizationsEnabled"] = "true"

	if err := k.keycloakAdmin.UpdateRealm(ctx, realmName, realmRep); err != nil {
		return fmt.Errorf("failed to enable Organizations for realm %s: %w", realmName, err)
	}

	return nil
}

func (k *KeycloakInitializer) initializeClient(ctx context.Context, client ClientConfig) error {
	k.logger.Info("Initializing client",
		zap.String("realm", client.RealmName),
		zap.String("client", client.ClientID))

	existingClientUUID, err := k.keycloakAdmin.GetClientUUID(ctx, client.RealmName, client.ClientID)
	k.logger.Debug("Checking for existing client",
		zap.String("realm", client.RealmName),
		zap.String("client", client.ClientID),
		zap.Bool("found", err == nil),
		zap.Error(err))
	if err == nil {
		k.logger.Info("Client already exists, updating configuration",
			zap.String("realm", client.RealmName),
			zap.String("client", client.ClientID))

		clientRep := &keycloak.ClientRepresentation{
			ClientID:                     client.ClientID,
			Enabled:                      true,
			StandardFlowEnabled:          client.StandardFlowEnabled,
			ServiceAccountsEnabled:       client.ServiceAccountsEnabled,
			DirectAccessGrantsEnabled:    client.DirectAccessGrantsEnabled,
			ImplicitFlowEnabled:          client.ImplicitFlowEnabled,
			RedirectUris:                 client.RedirectURIs,
			WebOrigins:                   client.WebOrigins,
			Protocol:                     "openid-connect",
			FullScopeAllowed:             true,
			Secret:                       client.Secret,
			ClientAuthenticatorType:      "client-secret",
			PublicClient:                 false,
			AuthorizationServicesEnabled: true,
		}

		if err := k.keycloakAdmin.UpdateClient(ctx, client.RealmName, existingClientUUID, clientRep); err != nil {
			return fmt.Errorf("failed to update client %s in realm %s: %w", client.ClientID, client.RealmName, err)
		}

		k.logger.Info("Client updated successfully",
			zap.String("realm", client.RealmName),
			zap.String("client", client.ClientID))

		if client.APIAudience != "" {
			if err := k.addAudienceMapper(ctx, client.RealmName, client.ClientID, client.APIAudience); err != nil {
				k.logger.Warn("Failed to add audience mapper",
					zap.String("client", client.ClientID),
					zap.String("audience", client.APIAudience),
					zap.Error(err))
			}
		}

		return nil
	}

	clientRep := &keycloak.ClientRepresentation{
		ClientID:                     client.ClientID,
		Enabled:                      true,
		StandardFlowEnabled:          client.StandardFlowEnabled,
		ServiceAccountsEnabled:       client.ServiceAccountsEnabled,
		DirectAccessGrantsEnabled:    client.DirectAccessGrantsEnabled,
		ImplicitFlowEnabled:          client.ImplicitFlowEnabled,
		RedirectUris:                 client.RedirectURIs,
		WebOrigins:                   client.WebOrigins,
		Protocol:                     "openid-connect",
		FullScopeAllowed:             true,
		Secret:                       client.Secret,
		ClientAuthenticatorType:      "client-secret",
		PublicClient:                 false,
		AuthorizationServicesEnabled: true,
	}

	if _, err := k.keycloakAdmin.CreateClient(ctx, client.RealmName, clientRep); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create client %s in realm %s: %w", client.ClientID, client.RealmName, err)
		}
		k.logger.Info("Client already exists",
			zap.String("realm", client.RealmName),
			zap.String("client", client.ClientID))
		return nil
	}

	k.logger.Info("Client created successfully",
		zap.String("realm", client.RealmName),
		zap.String("client", client.ClientID))

	if client.APIAudience != "" {
		if err := k.addAudienceMapper(ctx, client.RealmName, client.ClientID, client.APIAudience); err != nil {
			k.logger.Warn("Failed to add audience mapper",
				zap.String("client", client.ClientID),
				zap.String("audience", client.APIAudience),
				zap.Error(err))
		}
	}

	return nil
}

func (k *KeycloakInitializer) initializeRole(ctx context.Context, role RoleConfig) error {
	k.logger.Info("Initializing role",
		zap.String("realm", role.RealmName),
		zap.String("role", role.Name))

	existingRole, err := k.keycloakAdmin.GetRealmRole(ctx, role.RealmName, role.Name)
	if err == nil && existingRole != nil {
		k.logger.Info("Role already exists",
			zap.String("realm", role.RealmName),
			zap.String("role", role.Name))
		return nil
	}

	roleRep := &keycloak.RoleRepresentation{
		Name:        role.Name,
		Description: role.Description,
		Composite:   false,
	}

	if err := k.keycloakAdmin.CreateRole(ctx, role.RealmName, roleRep); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create role %s in realm %s: %w", role.Name, role.RealmName, err)
		}
		k.logger.Info("Role already exists",
			zap.String("realm", role.RealmName),
			zap.String("role", role.Name))
		return nil
	}

	k.logger.Info("Role created successfully",
		zap.String("realm", role.RealmName),
		zap.String("role", role.Name))
	return nil
}

func (k *KeycloakInitializer) initializeUser(ctx context.Context, user UserConfig) error {
	k.logger.Info("Initializing user",
		zap.String("realm", user.RealmName),
		zap.String("user", user.Username))

	existingUser, err := k.keycloakAdmin.GetUserByUsername(ctx, user.RealmName, user.Username)
	if err == nil && existingUser != nil {
		k.logger.Info("User already exists",
			zap.String("realm", user.RealmName),
			zap.String("user", user.Username))

		if len(user.Roles) > 0 {
			k.assignRolesToUser(ctx, user.RealmName, existingUser.ID, user.Roles)
		}
		return nil
	}

	userRep := &keycloak.UserRepresentation{
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Enabled:   user.Enabled,
		Credentials: []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     user.Password,
				Temporary: user.Temporary,
			},
		},
	}

	createdUser, err := k.keycloakAdmin.CreateUser(ctx, user.RealmName, userRep)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create user %s in realm %s: %w", user.Username, user.RealmName, err)
		}
		k.logger.Info("User already exists",
			zap.String("realm", user.RealmName),
			zap.String("user", user.Username))

		existingUser, err := k.keycloakAdmin.GetUserByUsername(ctx, user.RealmName, user.Username)
		if err != nil {
			return fmt.Errorf("failed to get existing user %s: %w", user.Username, err)
		}
		createdUser = existingUser
	} else {
		k.logger.Info("User created successfully",
			zap.String("realm", user.RealmName),
			zap.String("user", user.Username))
	}

	if len(user.Roles) > 0 && createdUser != nil {
		k.assignRolesToUser(ctx, user.RealmName, createdUser.ID, user.Roles)
	}

	return nil
}

func (k *KeycloakInitializer) assignRolesToUser(ctx context.Context, realmName, userID string, roleNames []string) {
	var roles []keycloak.RoleRepresentation

	for _, roleName := range roleNames {
		role, err := k.keycloakAdmin.GetRealmRole(ctx, realmName, roleName)
		if err != nil {
			k.logger.Warn("Failed to get role for assignment",
				zap.String("realm", realmName),
				zap.String("user", userID),
				zap.String("role", roleName),
				zap.Error(err))
			continue
		}
		if role != nil {
			roles = append(roles, *role)
		}
	}

	if len(roles) > 0 {
		if err := k.keycloakAdmin.AssignRealmRolesToUser(ctx, realmName, userID, roles); err != nil {
			k.logger.Warn("Failed to assign roles to user",
				zap.String("realm", realmName),
				zap.String("user", userID),
				zap.Strings("roles", roleNames),
				zap.Error(err))
		} else {
			k.logger.Info("Roles assigned to user",
				zap.String("realm", realmName),
				zap.String("user", userID),
				zap.Strings("roles", roleNames))
		}
	}
}

func (k *KeycloakInitializer) registerOIDCProvider(ctx context.Context, provider OIDCProviderConfig) error {
	k.logger.Info("Registering OIDC provider", zap.String("provider", provider.Name))

	keycloakProvider := auth.CreateKeycloakProvider(
		provider.Name,
		k.config.Keycloak.URL,
		provider.RealmName,
		provider.ClientID,
		provider.ClientSecret,
		provider.CallbackURL,
		k.config.Keycloak.APIAudience,
		k.config.Keycloak.SkipTLSVerify,
		k.config.Keycloak.CACertPath,
	)

	if err := k.oidcService.AddProvider(ctx, keycloakProvider); err != nil {
		return fmt.Errorf("failed to register OIDC provider %s: %w", provider.Name, err)
	}

	k.logger.Info("OIDC provider registered successfully", zap.String("provider", provider.Name))
	return nil
}

func (k *KeycloakInitializer) validateRealm(ctx context.Context, realmName string) error {
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", k.config.Keycloak.URL, realmName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("realm %s does not exist or is not accessible", realmName)
	}

	return nil
}

func (k *KeycloakInitializer) validateClient(ctx context.Context, realmName, clientID string) error {
	if err := k.validateRealm(ctx, realmName); err != nil {
		return err
	}

	_, err := k.keycloakAdmin.GetClientUUID(ctx, realmName, clientID)
	if err != nil {
		return fmt.Errorf("client %s not found in realm %s: %w", clientID, realmName, err)
	}

	return nil
}

func GetDefaultTestConfig(keycloakURL, callbackURL string) *InitializationConfig {
	if callbackURL == "" {
		callbackURL = "http://localhost:8081" + constants.PathAuthCallback
	}

	return &InitializationConfig{
		Realms: []RealmConfig{
			{
				Name:        "master",
				DisplayName: "MSP Realm",
				Enabled:     true,
			},
		},
		Clients: []ClientConfig{
			{
				RealmName:                 "master",
				ClientID:                  "msp-client",
				Secret:                    "msp-secret",
				RedirectURIs:              []string{"*"},
				WebOrigins:                []string{"*"},
				StandardFlowEnabled:       true,
				ServiceAccountsEnabled:    true,
				DirectAccessGrantsEnabled: true,
				ImplicitFlowEnabled:       false,
				PublicClient:              false,
				APIAudience:               "booli-admin-api",
			},
		},
		OIDCProviders: []OIDCProviderConfig{
			{
				Name:         "keycloak-msp",
				RealmName:    "master",
				ClientID:     "msp-client",
				ClientSecret: "msp-secret",
				CallbackURL:  callbackURL,
			},
		},
	}
}

func ParseConfigFromEnv() (*InitializationConfig, error) {
	config := &InitializationConfig{}

	if realmConfigStr := os.Getenv("KEYCLOAK_INIT_REALMS"); realmConfigStr != "" {
		var realms []RealmConfig
		if err := json.Unmarshal([]byte(realmConfigStr), &realms); err != nil {
			return nil, fmt.Errorf("failed to parse KEYCLOAK_INIT_REALMS: %w", err)
		}
		config.Realms = realms
	}

	if clientConfigStr := os.Getenv("KEYCLOAK_INIT_CLIENTS"); clientConfigStr != "" {
		var clients []ClientConfig
		if err := json.Unmarshal([]byte(clientConfigStr), &clients); err != nil {
			return nil, fmt.Errorf("failed to parse KEYCLOAK_INIT_CLIENTS: %w", err)
		}
		config.Clients = clients
	}

	if oidcConfigStr := os.Getenv("KEYCLOAK_INIT_OIDC_PROVIDERS"); oidcConfigStr != "" {
		var oidcProviders []OIDCProviderConfig
		if err := json.Unmarshal([]byte(oidcConfigStr), &oidcProviders); err != nil {
			return nil, fmt.Errorf("failed to parse KEYCLOAK_INIT_OIDC_PROVIDERS: %w", err)
		}
		config.OIDCProviders = oidcProviders
	}

	realmName := os.Getenv("KEYCLOAK_MSP_REALM")
	if realmName == "" {
		realmName = "master"
	}

	enabled := true
	if enabledStr := os.Getenv("KEYCLOAK_MSP_REALM_ENABLED"); enabledStr != "" {
		enabled, _ = strconv.ParseBool(enabledStr)
	}

	if enabled {
		displayName := os.Getenv("KEYCLOAK_MSP_REALM_DISPLAY_NAME")
		if displayName == "" {
			displayName = "MSP Realm"
		}

		config.Realms = append(config.Realms, RealmConfig{
			Name:        realmName,
			DisplayName: displayName,
			Enabled:     true,
		})
	}

	clientID := os.Getenv("KEYCLOAK_MSP_CLIENT_ID")
	if clientID == "" {
		clientID = "msp-client"
	}

	clientSecret := os.Getenv("KEYCLOAK_MSP_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "msp-secret"
	}

	redirectURIs := []string{"http://localhost:8081" + constants.PathAuthCallback}
	if redirectURIsStr := os.Getenv("KEYCLOAK_MSP_CLIENT_REDIRECT_URIS"); redirectURIsStr != "" {
		redirectURIs = strings.Split(redirectURIsStr, ",")
	}

	webOrigins := []string{"http://localhost:8081"}
	if webOriginsStr := os.Getenv("KEYCLOAK_MSP_CLIENT_WEB_ORIGINS"); webOriginsStr != "" {
		webOrigins = strings.Split(webOriginsStr, ",")
	}

	standardFlow := true
	if standardFlowStr := os.Getenv("KEYCLOAK_MSP_CLIENT_STANDARD_FLOW"); standardFlowStr != "" {
		standardFlow, _ = strconv.ParseBool(standardFlowStr)
	}

	serviceAccounts := true
	if serviceAccountsStr := os.Getenv("KEYCLOAK_MSP_CLIENT_SERVICE_ACCOUNTS"); serviceAccountsStr != "" {
		serviceAccounts, _ = strconv.ParseBool(serviceAccountsStr)
	}

	directAccess := true
	if directAccessStr := os.Getenv("KEYCLOAK_MSP_CLIENT_DIRECT_ACCESS"); directAccessStr != "" {
		directAccess, _ = strconv.ParseBool(directAccessStr)
	}

	implicitFlow := false
	if implicitFlowStr := os.Getenv("KEYCLOAK_MSP_CLIENT_IMPLICIT_FLOW"); implicitFlowStr != "" {
		implicitFlow, _ = strconv.ParseBool(implicitFlowStr)
	}

	publicClient := false
	if publicClientStr := os.Getenv("KEYCLOAK_MSP_CLIENT_PUBLIC"); publicClientStr != "" {
		publicClient, _ = strconv.ParseBool(publicClientStr)
	}

	config.Clients = append(config.Clients, ClientConfig{
		RealmName:                 realmName,
		ClientID:                  clientID,
		Secret:                    clientSecret,
		RedirectURIs:              redirectURIs,
		WebOrigins:                webOrigins,
		StandardFlowEnabled:       standardFlow,
		ServiceAccountsEnabled:    serviceAccounts,
		DirectAccessGrantsEnabled: directAccess,
		ImplicitFlowEnabled:       implicitFlow,
		PublicClient:              publicClient,
		APIAudience:               "booli-admin-api",
	})

	mspRoles := []RoleConfig{
		{RealmName: realmName, Name: "msp-admin", Description: "MSP Administrator - Cross-organization management"},
		{RealmName: realmName, Name: "msp-power", Description: "MSP Power User - Advanced MSP features"},
		{RealmName: realmName, Name: "msp-basic", Description: "MSP Basic User - Standard MSP features"},
		{RealmName: realmName, Name: "tenant-admin", Description: "Tenant Administrator - Full administrative access within own tenant"},
	}
	config.Roles = append(config.Roles, mspRoles...)

	adminConfig, err := GetDefaultMSPAdminConfig(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get MSP admin config: %w", err)
	}

	firstName := os.Getenv("KEYCLOAK_MSP_DEFAULT_USER_FIRST_NAME")
	if firstName == "" {
		firstName = "Admin"
	}

	lastName := os.Getenv("KEYCLOAK_MSP_DEFAULT_USER_LAST_NAME")
	if lastName == "" {
		lastName = "User"
	}

	roles := []string{"msp-admin"}
	if rolesStr := os.Getenv("KEYCLOAK_MSP_DEFAULT_USER_ROLES"); rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
		for i, role := range roles {
			roles[i] = strings.TrimSpace(role)
		}
	}

	user := UserConfig{
		RealmName: realmName,
		Username:  adminConfig.Username,
		Password:  adminConfig.Password,
		Email:     adminConfig.Email,
		FirstName: firstName,
		LastName:  lastName,
		Roles:     roles,
		Enabled:   true,
		Temporary: adminConfig.ForcePasswordChange,
	}

	config.Users = append(config.Users, user)

	oidcProvider := OIDCProviderConfig{
		Name:         "keycloak",
		RealmName:    realmName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CallbackURL:  "http://localhost:8081" + constants.PathAuthCallback,
	}
	config.OIDCProviders = append(config.OIDCProviders, oidcProvider)

	return config, nil
}

func (k *KeycloakInitializer) setupRealmPermissions(ctx context.Context, realmName string) error {
	return k.permissionService.SetupRealmPermissions(ctx, realmName)
}

func (k *KeycloakInitializer) addAudienceMapper(ctx context.Context, realmName, clientID, apiAudience string) error {
	clientUUID, err := k.keycloakAdmin.GetClientUUID(ctx, realmName, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client UUID: %w", err)
	}

	mapperConfig := &keycloak.ProtocolMapperRepresentation{
		Name:           fmt.Sprintf("%s-audience", apiAudience),
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-audience-mapper",
		Config: map[string]string{
			"included.client.audience": apiAudience,
			"access.token.claim":       "true",
			"id.token.claim":           "false",
		},
	}

	if err := k.keycloakAdmin.CreateProtocolMapper(ctx, realmName, clientUUID, mapperConfig); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create audience mapper: %w", err)
		}
	}

	k.logger.Info("Audience mapper added successfully",
		zap.String("client", clientID),
		zap.String("audience", apiAudience))

	return nil
}
