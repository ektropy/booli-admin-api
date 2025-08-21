package migrations

import (
	"github.com/booli/booli-admin-api/internal/models"
	"gorm.io/gorm"
)

func CreateMSPTables(db *gorm.DB) error {
	// Create MSP table
	if err := db.AutoMigrate(&models.MSP{}); err != nil {
		return err
	}

	// Add ParentMSP column to Tenant table if it doesn't exist
	if !db.Migrator().HasColumn(&models.Tenant{}, "parent_msp") {
		if err := db.Migrator().AddColumn(&models.Tenant{}, "parent_msp"); err != nil {
			return err
		}
	}

	// Create index on ParentMSP for faster queries
	if !db.Migrator().HasIndex(&models.Tenant{}, "idx_tenant_parent_msp") {
		if err := db.Migrator().CreateIndex(&models.Tenant{}, "idx_tenant_parent_msp"); err != nil {
			return err
		}
	}

	// Create index on MSP status for faster queries
	if !db.Migrator().HasIndex(&models.MSP{}, "idx_msp_status") {
		if err := db.Migrator().CreateIndex(&models.MSP{}, "idx_msp_status"); err != nil {
			return err
		}
	}

	return nil
}