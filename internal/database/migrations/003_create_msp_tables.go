package migrations

import (
	"github.com/booli/booli-admin-api/internal/models"
	"gorm.io/gorm"
)

func CreateMSPTables(db *gorm.DB) error {
	if err := db.AutoMigrate(&models.MSP{}); err != nil {
		return err
	}

	if !db.Migrator().HasColumn(&models.Tenant{}, "parent_msp") {
		if err := db.Migrator().AddColumn(&models.Tenant{}, "parent_msp"); err != nil {
			return err
		}
	}

	if !db.Migrator().HasIndex(&models.Tenant{}, "idx_tenant_parent_msp") {
		if err := db.Migrator().CreateIndex(&models.Tenant{}, "idx_tenant_parent_msp"); err != nil {
			return err
		}
	}

	if !db.Migrator().HasIndex(&models.MSP{}, "idx_msp_status") {
		if err := db.Migrator().CreateIndex(&models.MSP{}, "idx_msp_status"); err != nil {
			return err
		}
	}

	return nil
}