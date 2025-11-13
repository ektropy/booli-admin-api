package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

type FGAPPolicyRole struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type FGAPPolicy struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Logic       string                 `json:"logic,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Roles       []FGAPPolicyRole       `json:"roles,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Resources   []string               `json:"resources,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type FGAPResource struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name"`
	Type        string            `json:"type,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
}

type FGAPScope struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	IconURI     string `json:"iconUri,omitempty"`
}

type PermissionTemplate struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Scopes         []string `json:"scopes"`
	ResourceFilter string   `json:"resource_filter"`
	Conditions     []string `json:"conditions,omitempty"`
}

type ServerInfo struct {
	SystemInfo SystemInfo `json:"systemInfo"`
}

type SystemInfo struct {
	Version string `json:"version"`
}

var MSPPermissionTemplates = map[string]PermissionTemplate{
	"msp-admin": {
		Name:        "MSP Administrator",
		Description: "Full administrative access to MSP and client tenants",
		Scopes: []string{
			"manage-realm",
			"manage-users",
			"view-users",
			"manage-clients",
			"view-clients",
			"manage-groups",
			"view-groups",
			"manage-smtp",
			"view-events",
			"view-realm",
		},
		ResourceFilter: "client-realms-pattern",
		Conditions:     []string{"msp-employee"},
	},
	"msp-power": {
		Name:        "MSP Power User",
		Description: "Advanced MSP operations for assigned clients",
		Scopes: []string{
			"manage-users",
			"view-users",
			"manage-groups",
			"view-groups",
			"view-clients",
			"view-events",
		},
		ResourceFilter: "assigned-clients-only",
		Conditions:     []string{"business-hours", "assigned-clients"},
	},
	"tenant-admin": {
		Name:        "Tenant Administrator",
		Description: "Full administrative access within own tenant",
		Scopes: []string{
			"manage-realm",
			"manage-users",
			"view-users",
			"manage-groups",
			"view-groups",
			"view-events",
		},
		ResourceFilter: "own-realm-only",
		Conditions:     []string{"own-tenant-only"},
	},
}

func (c *AdminClient) EnableFGAPv2(ctx context.Context, realmName string) error {
	serverInfo, err := c.GetServerInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Keycloak version: %w", err)
	}

	if !c.isVersionSupported(serverInfo.SystemInfo.Version) {
		return fmt.Errorf("Keycloak version %s does not support FGAP V2. Minimum required version is 26.2.0", serverInfo.SystemInfo.Version)
	}

	c.logger.Info("Enabling FGAP for realm",
		zap.String("realm", realmName),
		zap.String("keycloak_version", serverInfo.SystemInfo.Version))

	realmUpdate := map[string]interface{}{
		"adminPermissionsEnabled": true,
		"adminPermissionsClient": map[string]interface{}{
			"clientId": "admin-permissions",
		},
	}

	if err := c.updateRealmPartial(ctx, realmName, realmUpdate); err != nil {
		return fmt.Errorf("failed to enable FGAP v2 for realm %s: %w", realmName, err)
	}

	adminPermClientID, err := c.GetClientUUID(ctx, realmName, "admin-permissions")
	if err == nil {
		c.logger.Info("admin-permissions client was created successfully",
			zap.String("realm", realmName),
			zap.String("client_uuid", adminPermClientID))
	} else {
		c.logger.Warn("admin-permissions client was not created after enabling FGAP",
			zap.String("realm", realmName),
			zap.Error(err))
	}

	c.logger.Info("FGAPv2 enabled successfully", zap.String("realm", realmName))
	return nil
}

func (c *AdminClient) GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	resp, err := c.makeRequestToPath(ctx, "GET", "/admin/serverinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.logger.Debug("Server info request failed",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(bodyBytes)))
		return nil, fmt.Errorf("get server info failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var serverInfo ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&serverInfo); err != nil {
		return nil, fmt.Errorf("failed to decode server info: %w", err)
	}

	return &serverInfo, nil
}

func (c *AdminClient) makeRequestToPath(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = strings.NewReader(string(jsonBody))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.getAccessToken(ctx); err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

func (c *AdminClient) isVersionSupported(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	return major > 26 || (major == 26 && minor >= 2)
}

func (c *AdminClient) updateRealmPartial(ctx context.Context, realmName string, updates map[string]interface{}) error {
	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal realm updates: %w", err)
	}

	resp, err := c.makeRequestToPath(ctx, "PUT", "/admin/realms/"+realmName, json.RawMessage(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to update realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update realm failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (c *AdminClient) CreatePermissionPolicy(ctx context.Context, realmName, roleName string, template PermissionTemplate) error {
	c.logger.Info("Creating permission policy",
		zap.String("realm", realmName),
		zap.String("role", roleName),
		zap.String("template", template.Name))

	clientUUID, err := c.getAdminPermissionsClientUUID(ctx, realmName)
	if err != nil {
		return fmt.Errorf("failed to get admin permissions client: %w", err)
	}

	roleID, err := c.getRoleID(ctx, realmName, roleName)
	if err != nil {
		return fmt.Errorf("failed to get role ID for %s: %w", roleName, err)
	}

	policy := FGAPPolicy{
		Name:        fmt.Sprintf("%s-policy", roleName),
		Type:        "role",
		Logic:       "POSITIVE",
		Roles:       []FGAPPolicyRole{{ID: roleID, Required: false}},
		Description: template.Description,
	}

	if err := c.createFGAPPolicy(ctx, realmName, clientUUID, &policy); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Create scope permissions for each scope in the template
	for _, scope := range template.Scopes {
		if err := c.createScopePermission(ctx, realmName, clientUUID, roleName, scope, template.ResourceFilter); err != nil {
			c.logger.Warn("Failed to create scope permission",
				zap.String("realm", realmName),
				zap.String("role", roleName),
				zap.String("scope", scope),
				zap.Error(err))
			// Continue creating other permissions even if one fails
		}
	}

	c.logger.Info("Permission policy and permissions created successfully",
		zap.String("realm", realmName),
		zap.String("role", roleName),
		zap.Strings("scopes", template.Scopes))
	return nil
}

func (c *AdminClient) AssignRoleWithPermissions(ctx context.Context, realmName, userID, roleName string) error {
	c.logger.Info("Assigning role with permissions",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))

	template, exists := MSPPermissionTemplates[roleName]
	if !exists {
		return fmt.Errorf("permission template not found for role: %s", roleName)
	}

	roleRep := &RoleRepresentation{
		Name:        roleName,
		Description: template.Description,
	}
	if err := c.CreateRole(ctx, realmName, roleRep); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			c.logger.Warn("Failed to create role before assignment",
				zap.String("realm", realmName),
				zap.String("role", roleName),
				zap.Error(err))
		}
	}

	if err := c.AssignRealmRoleToUser(ctx, realmName, userID, roleName); err != nil {
		return fmt.Errorf("failed to assign realm role: %w", err)
	}

	if roleName == "msp-admin" || roleName == "msp-power" {
		if err := c.grantKeycloakClientRoles(ctx, realmName, userID, template.Scopes); err != nil {
			c.logger.Warn("Failed to grant Keycloak client roles",
				zap.String("realm", realmName),
				zap.String("user_id", userID),
				zap.Error(err))
		}
	}

	c.logger.Info("Role with permissions assigned successfully",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))
	return nil
}

func (c *AdminClient) HasPermissionScope(ctx context.Context, realmName, userID, scope, resource string) (bool, error) {
	roles, err := c.GetUserRealmRoles(ctx, realmName, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}

	for _, role := range roles {
		template, exists := MSPPermissionTemplates[role.Name]
		if !exists {
			continue
		}

		for _, templateScope := range template.Scopes {
			if templateScope == scope {
				if c.checkResourceFilter(template.ResourceFilter, resource, realmName) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (c *AdminClient) GetUserEffectiveScopes(ctx context.Context, realmName, userID string) ([]string, error) {
	roles, err := c.GetUserRealmRoles(ctx, realmName, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	scopeSet := make(map[string]bool)
	for _, role := range roles {
		template, exists := MSPPermissionTemplates[role.Name]
		if !exists {
			continue
		}

		for _, scope := range template.Scopes {
			scopeSet[scope] = true
		}
	}

	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

func (c *AdminClient) getAdminPermissionsClientUUID(ctx context.Context, realmName string) (string, error) {
	c.logger.Debug("Looking for admin-permissions client", zap.String("realm", realmName))

	clientUUID, err := c.GetClientUUID(ctx, realmName, "admin-permissions")
	if err == nil {
		c.logger.Debug("Found admin-permissions client",
			zap.String("realm", realmName),
			zap.String("uuid", clientUUID))
		return clientUUID, nil
	}

	c.logger.Debug("admin-permissions client not found, trying realm-management client",
		zap.String("realm", realmName),
		zap.Error(err))

	clientUUID, err = c.GetClientUUID(ctx, realmName, "realm-management")
	if err != nil {
		return "", fmt.Errorf("neither admin-permissions nor realm-management found in realm %s: %w", realmName, err)
	}

	if err := c.enableAuthorizationServices(ctx, realmName, clientUUID); err != nil {
		c.logger.Warn("Failed to enable authorization services on msp-client",
			zap.String("realm", realmName),
			zap.Error(err))
	}

	return clientUUID, nil
}

func (c *AdminClient) enableAuthorizationServices(ctx context.Context, realmName, clientUUID string) error {
	client, err := c.GetClient(ctx, realmName, clientUUID)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}

	if !client.AuthorizationServicesEnabled {
		client.AuthorizationServicesEnabled = true
		if err := c.UpdateClient(ctx, realmName, clientUUID, client); err != nil {
			return fmt.Errorf("failed to enable authorization services: %w", err)
		}
		c.logger.Info("Authorization services enabled on client",
			zap.String("realm", realmName),
			zap.String("client", clientUUID))
	}

	return nil
}

func (c *AdminClient) createFGAPPolicy(ctx context.Context, realmName, clientUUID string, policy *FGAPPolicy) error {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/policy/role", realmName, clientUUID)

	resp, err := c.makeRequest(ctx, "POST", endpoint, policy)
	if err != nil {
		return fmt.Errorf("failed to create FGAP policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create FGAP policy failed with status %d", resp.StatusCode)
	}

	return nil
}

func (c *AdminClient) createScopePermission(ctx context.Context, realmName, clientUUID, roleName, scope, resourceFilter string) error {
	rolePolicyID, err := c.getPolicyID(ctx, realmName, clientUUID, fmt.Sprintf("%s-policy", roleName))
	if err != nil {
		return fmt.Errorf("failed to get role policy ID: %w", err)
	}

	availableScopes, err := c.listAvailableScopes(ctx, realmName, clientUUID)
	if err != nil {
		c.logger.Debug("Failed to get available scopes", zap.Error(err))
	} else {
		c.logger.Debug("Available scopes in authorization server",
			zap.String("realm", realmName),
			zap.Int("scope_count", len(availableScopes)))

		scopeExists := false
		for _, availableScope := range availableScopes {
			c.logger.Debug("Found scope",
				zap.String("scope_name", availableScope.Name),
				zap.String("scope_id", availableScope.ID))
			if availableScope.Name == scope {
				scopeExists = true
			}
		}

		if !scopeExists {
			c.logger.Debug("Required scope does not exist in authorization server, creating it",
				zap.String("required_scope", scope))
			if err := c.createScope(ctx, realmName, clientUUID, scope); err != nil {
				c.logger.Warn("Failed to create scope",
					zap.String("scope", scope),
					zap.Error(err))
				return fmt.Errorf("failed to create scope %s: %w", scope, err)
			}
		}
	}

	permissionData := map[string]interface{}{
		"name":        fmt.Sprintf("%s-%s-permission", roleName, scope),
		"type":        "scope",
		"logic":       "POSITIVE",
		"scopes":      []string{scope},
		"description": fmt.Sprintf("Permission for %s to %s", roleName, scope),
		"policies":    []string{rolePolicyID},
	}

	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/permission/scope", realmName, clientUUID)

	c.logger.Debug("Creating scope permission",
		zap.String("realm", realmName),
		zap.String("role", roleName),
		zap.String("scope", scope),
		zap.String("endpoint", endpoint),
		zap.Any("permission", permissionData))

	resp, err := c.makeRequest(ctx, "POST", endpoint, permissionData)
	if err != nil {
		return fmt.Errorf("failed to create scope permission: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.logger.Debug("Scope permission creation failed",
			zap.String("realm", realmName),
			zap.String("role", roleName),
			zap.String("scope", scope),
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(bodyBytes)))
		return fmt.Errorf("create scope permission failed with status %d", resp.StatusCode)
	}

	return nil
}

func (c *AdminClient) grantKeycloakClientRoles(ctx context.Context, realmName, userID string, scopes []string) error {
	realmMgmtClientUUID, err := c.GetClientUUID(ctx, realmName, "realm-management")
	if err != nil {
		c.logger.Debug("realm-management client not found, skipping client role assignment")
		return nil
	}

	clientRoles := c.mapScopesToClientRoles(scopes)

	for _, roleName := range clientRoles {
		if err := c.assignClientRoleToUser(ctx, realmName, userID, realmMgmtClientUUID, roleName); err != nil {
			c.logger.Warn("Failed to assign client role",
				zap.String("realm", realmName),
				zap.String("user_id", userID),
				zap.String("role", roleName),
				zap.Error(err))
		}
	}

	return nil
}

func (c *AdminClient) mapScopesToClientRoles(scopes []string) []string {
	roleMap := map[string]string{
		"manage-realm":   "realm-admin",
		"view-realm":     "view-realm",
		"manage-users":   "manage-users",
		"view-users":     "view-users",
		"manage-clients": "manage-clients",
		"view-clients":   "view-clients",
		"manage-groups":  "manage-users",
		"view-groups":    "view-users",
		"manage-smtp":    "manage-realm",
		"view-events":    "view-events",
	}

	roleSet := make(map[string]bool)
	for _, scope := range scopes {
		if role, exists := roleMap[scope]; exists {
			roleSet[role] = true
		}
	}

	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	return roles
}

func (c *AdminClient) assignClientRoleToUser(ctx context.Context, realmName, userID, clientUUID, roleName string) error {
	roles, err := c.getClientRoles(ctx, realmName, clientUUID, roleName)
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		return fmt.Errorf("client role %s not found", roleName)
	}

	endpoint := fmt.Sprintf("/%s/users/%s/role-mappings/clients/%s", realmName, userID, clientUUID)

	resp, err := c.makeRequest(ctx, "POST", endpoint, roles)
	if err != nil {
		return fmt.Errorf("failed to assign client role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("assign client role failed with status %d", resp.StatusCode)
	}

	return nil
}

func (c *AdminClient) getClientRoles(ctx context.Context, realmName, clientUUID, roleName string) ([]RoleRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/roles/%s", realmName, clientUUID, roleName)

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get client role failed with status %d", resp.StatusCode)
	}

	var role RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, fmt.Errorf("failed to decode client role: %w", err)
	}

	return []RoleRepresentation{role}, nil
}

func (c *AdminClient) checkResourceFilter(filter, resource, realmName string) bool {
	switch filter {
	case "own-realm-only":
		return resource == realmName
	case "client-realms-pattern":
		if resource == realmName {
			return true
		}
		return c.isClientRealmForMSP(resource, realmName)
	case "assigned-clients-only":
		return c.isAssignedClient(resource, realmName)
	default:
		return true
	}
}

func (c *AdminClient) isClientRealmForMSP(clientRealm, mspRealm string) bool {
	if !strings.HasPrefix(mspRealm, "msp-") {
		return false
	}

	mspName := strings.TrimPrefix(mspRealm, "msp-")
	expectedPrefix := fmt.Sprintf("%s-client-", mspName)

	return strings.HasPrefix(clientRealm, expectedPrefix)
}

func (c *AdminClient) isAssignedClient(clientRealm, userRealm string) bool {
	return c.isClientRealmForMSP(clientRealm, userRealm)
}

func (c *AdminClient) getRoleID(ctx context.Context, realmName, roleName string) (string, error) {
	endpoint := fmt.Sprintf("/%s/roles/%s", realmName, roleName)

	c.logger.Debug("Looking up role ID",
		zap.String("realm", realmName),
		zap.String("role", roleName),
		zap.String("endpoint", endpoint))

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		c.logger.Error("Role lookup request failed",
			zap.String("realm", realmName),
			zap.String("role", roleName),
			zap.Error(err))
		return "", fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.logger.Error("Role lookup failed",
			zap.String("realm", realmName),
			zap.String("role", roleName),
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(bodyBytes)))
		return "", fmt.Errorf("get role failed with status %d", resp.StatusCode)
	}

	var role RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return "", fmt.Errorf("failed to decode role: %w", err)
	}

	return role.ID, nil
}

func (c *AdminClient) getPolicyID(ctx context.Context, realmName, clientUUID, policyName string) (string, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/policy", realmName, clientUUID)

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get policies failed with status %d", resp.StatusCode)
	}

	var policies []FGAPPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return "", fmt.Errorf("failed to decode policies: %w", err)
	}

	for _, policy := range policies {
		if policy.Name == policyName {
			return policy.ID, nil
		}
	}

	return "", fmt.Errorf("policy %s not found", policyName)
}

func (c *AdminClient) listAvailableScopes(ctx context.Context, realmName, clientUUID string) ([]FGAPScope, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/scope", realmName, clientUUID)

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get scopes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get scopes failed with status %d", resp.StatusCode)
	}

	var scopes []FGAPScope
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		return nil, fmt.Errorf("failed to decode scopes: %w", err)
	}

	return scopes, nil
}

func (c *AdminClient) createScope(ctx context.Context, realmName, clientUUID, scopeName string) error {
	scope := FGAPScope{
		Name:        scopeName,
		DisplayName: scopeName,
	}

	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/scope", realmName, clientUUID)

	resp, err := c.makeRequest(ctx, "POST", endpoint, scope)
	if err != nil {
		return fmt.Errorf("failed to create scope: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.logger.Debug("Scope creation failed",
			zap.String("scope", scopeName),
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(bodyBytes)))
		return fmt.Errorf("create scope failed with status %d", resp.StatusCode)
	}

	c.logger.Debug("Scope created successfully", zap.String("scope", scopeName))
	return nil
}
