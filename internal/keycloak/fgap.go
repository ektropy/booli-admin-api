package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type FGAPPolicy struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Logic       string                 `json:"logic,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
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

var MSPPermissionTemplates = map[string]PermissionTemplate{
	"msp-admin": {
		Name:        "MSP Administrator",
		Description: "Full administrative access to MSP and client tenants",
		Scopes: []string{
			"manage-realm",
			"manage-users", 
			"manage-clients",
			"manage-groups",
			"manage-smtp",
			"view-events",
		},
		ResourceFilter: "client-realms-pattern",
		Conditions:     []string{"msp-employee"},
	},
	"msp-power": {
		Name:        "MSP Power User",
		Description: "Advanced MSP operations for assigned clients",
		Scopes: []string{
			"manage-users",
			"manage-groups", 
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
			"manage-users",
			"manage-groups",
			"view-events",
		},
		ResourceFilter: "own-realm-only",
		Conditions:     []string{"own-tenant-only"},
	},
}

func (c *AdminClient) EnableFGAPv2(ctx context.Context, realmName string) error {
	c.logger.Info("Enabling FGAPv2 for realm", zap.String("realm", realmName))

	realmRep, err := c.GetRealm(ctx, realmName)
	if err != nil {
		return fmt.Errorf("failed to get realm %s: %w", realmName, err)
	}

	if realmRep.Attributes == nil {
		realmRep.Attributes = make(map[string]string)
	}
	realmRep.Attributes["adminPermissionsEnabled"] = "true"

	if err := c.UpdateRealm(ctx, realmName, realmRep); err != nil {
		return fmt.Errorf("failed to enable FGAP v2 for realm %s: %w", realmName, err)
	}

	c.logger.Info("FGAPv2 enabled successfully", zap.String("realm", realmName))
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

	policy := FGAPPolicy{
		Name:        fmt.Sprintf("%s-policy", roleName),
		Type:        "role",
		Logic:       "POSITIVE",
		Roles:       []string{roleName},
		Description: template.Description,
	}

	if err := c.createFGAPPolicy(ctx, realmName, clientUUID, &policy); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	for _, scope := range template.Scopes {
		if err := c.createScopePermission(ctx, realmName, clientUUID, roleName, scope, template.ResourceFilter); err != nil {
			c.logger.Warn("Failed to create scope permission",
				zap.String("realm", realmName),
				zap.String("role", roleName),
				zap.String("scope", scope),
				zap.Error(err))
		}
	}

	c.logger.Info("Permission policy created successfully",
		zap.String("realm", realmName),
		zap.String("role", roleName))
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
	clientUUID, err := c.GetClientUUID(ctx, realmName, "admin-permissions")
	if err != nil {
		return "", fmt.Errorf("admin-permissions client not found in realm %s: %w", realmName, err)
	}
	return clientUUID, nil
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
	permission := FGAPPolicy{
		Name:        fmt.Sprintf("%s-%s-permission", roleName, scope),
		Type:        "scope",
		Logic:       "POSITIVE",
		Scopes:      []string{scope},
		Description: fmt.Sprintf("Permission for %s to %s", roleName, scope),
	}

	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/permission/scope", realmName, clientUUID)

	resp, err := c.makeRequest(ctx, "POST", endpoint, permission)
	if err != nil {
		return fmt.Errorf("failed to create scope permission: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
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
		"manage-realm":  "realm-admin",
		"manage-users":  "manage-users",
		"manage-clients": "manage-clients",
		"manage-groups": "manage-users",
		"manage-smtp":   "manage-realm",
		"view-events":   "view-events",
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