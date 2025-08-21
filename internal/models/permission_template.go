package models

type MSPConfig struct {
	MSPRealm         string   `json:"msp_realm"`
	ClientPattern    string   `json:"client_pattern"`
	AdminUsers       []string `json:"admin_users,omitempty"`
	PowerUsers       []string `json:"power_users,omitempty"`
	IsolationEnabled bool     `json:"isolation_enabled"`
	MaxClientTenants int      `json:"max_client_tenants,omitempty"`
	MaxAdminUsers    int      `json:"max_admin_users,omitempty"`
}