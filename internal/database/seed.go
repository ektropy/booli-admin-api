package database

import (
	"encoding/json"
	"os"

	"github.com/booli/booli-admin-api/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func tenantSettingsToJSON(settings models.TenantSettings) datatypes.JSON {
	data, _ := json.Marshal(settings)
	return datatypes.JSON(data)
}

func SeedDevelopmentData(db *gorm.DB) error {
	env := os.Getenv("BOOLI_ENVIRONMENT")
	if env != "development" && env != "test" {
		return nil
	}

	if err := createMSPTenant(db); err != nil {
		return err
	}

	if err := createTestTenants(db); err != nil {
		return err
	}

	if err := createTestUsers(db); err != nil {
		return err
	}

	return nil
}

func SeedProductionData(db *gorm.DB) error {
	env := os.Getenv("BOOLI_ENVIRONMENT")
	if env == "development" || env == "test" {
		return nil
	}

	if err := createMSPTenant(db); err != nil {
		return err
	}

	return nil
}

func createTestTenants(db *gorm.DB) error {
	testTenants := []models.Tenant{
		{
			Name:   "Acme Corporation",
			Domain: "acme.example.com",
			Active: true,
			Type:   models.TenantTypeClient,
			Settings: tenantSettingsToJSON(models.TenantSettings{
				EnableSSO:         true,
				EnableMFA:         false,
				EnableAudit:       true,
				MaxUsers:          1000,
				MaxRoles:          50,
				MaxSSOProviders:   5,
				DataRetentionDays: 365,
				ComplianceFlags:   []string{"SOC2"},
			}),
		},
		{
			Name:   "Demo Company",
			Domain: "demo.example.com",
			Active: true,
			Type:   models.TenantTypeClient,
			Settings: tenantSettingsToJSON(models.TenantSettings{
				EnableSSO:         false,
				EnableMFA:         true,
				EnableAudit:       true,
				MaxUsers:          500,
				MaxRoles:          25,
				MaxSSOProviders:   3,
				DataRetentionDays: 180,
				ComplianceFlags:   []string{"GDPR"},
			}),
		},
		{
			Name:   "Test MSP Partner",
			Domain: "partner.example.com",
			Active: true,
			Type:   models.TenantTypeMSP,
			Settings: tenantSettingsToJSON(models.TenantSettings{
				EnableSSO:         true,
				EnableMFA:         true,
				EnableAudit:       true,
				MaxUsers:          2000,
				MaxRoles:          100,
				MaxSSOProviders:   10,
				DataRetentionDays: 730,
				ComplianceFlags:   []string{"SOC2", "HIPAA"},
			}),
		},
	}

	for _, tenant := range testTenants {
		var existingTenant models.Tenant
		err := db.Where("name = ?", tenant.Name).First(&existingTenant).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				if err := db.Create(&tenant).Error; err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	return nil
}

func createTestUsers(db *gorm.DB) error {
	var mspTenant models.Tenant
	err := db.Where("type = ?", models.TenantTypeMSP).First(&mspTenant).Error
	if err != nil {
		return err
	}

	var acmeTenant models.Tenant
	err = db.Where("name = ?", "Acme Corporation").First(&acmeTenant).Error
	if err != nil {
		return err
	}

	return nil
}

func createMSPTenant(db *gorm.DB) error {
	mspName := os.Getenv("BOOLI_MSP_NAME")
	if mspName == "" {
		mspName = "MSP Organization"
	}

	mspDomain := os.Getenv("BOOLI_MSP_DOMAIN")
	if mspDomain == "" {
		mspDomain = "msp.local"
	}

	mspTenant := &models.Tenant{
		Name:   mspName,
		Domain: mspDomain,
		Active: true,
		Type:   models.TenantTypeMSP,
		Settings: tenantSettingsToJSON(models.TenantSettings{
			EnableSSO:         true,
			EnableMFA:         true,
			EnableAudit:       true,
			MaxUsers:          -1,
			MaxRoles:          -1,
			MaxSSOProviders:   -1,
			DataRetentionDays: 2555,
			ComplianceFlags:   []string{"SOC2", "GDPR"},
		}),
	}

	var existingTenant models.Tenant
	err := db.Where("type = ?", models.TenantTypeMSP).First(&existingTenant).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return db.Create(mspTenant).Error
		}
		return err
	}
	return nil
}

