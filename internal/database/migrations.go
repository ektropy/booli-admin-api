package database

import (
	"os"

	"github.com/booli/booli-admin-api/internal/models"
	"gorm.io/gorm"
)

func Initialize(db *gorm.DB) error {
	if err := CreateExtensions(db); err != nil {
		return err
	}

	if err := db.AutoMigrate(
		&models.Tenant{},
		&models.SSOProvider{},
		&models.AuditLog{},
		&models.TenantEnvironment{},
		&models.NetworkRange{},
		&models.PublicIP{},
		&models.EgressIP{},
		&models.Domain{},
		&models.NamingConvention{},
		&models.InfrastructureIP{},
		&models.TenantAccessGrant{},
	); err != nil {
		return err
	}

	if err := CreateIndexes(db); err != nil {
		return err
	}

	if err := SetupRowLevelSecurity(db); err != nil {
		return err
	}

	if os.Getenv("BOOLI_ENVIRONMENT") != "test" {
		if err := SeedDevelopmentData(db); err != nil {
			return err
		}
	}

	if err := SeedProductionData(db); err != nil {
		return err
	}

	return nil
}

func DropAllTables(db *gorm.DB) error {
	return db.Migrator().DropTable(
		&models.TenantAccessGrant{},
		&models.InfrastructureIP{},
		&models.NamingConvention{},
		&models.Domain{},
		&models.EgressIP{},
		&models.PublicIP{},
		&models.NetworkRange{},
		&models.TenantEnvironment{},
		&models.AuditLog{},
		&models.SSOProvider{},
		&models.Tenant{},
	)
}
