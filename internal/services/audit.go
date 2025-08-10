package services

import (
	"context"
	"fmt"
	"time"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuditService struct {
	db     *gorm.DB
	logger *zap.Logger
	config *config.Config
}

func NewAuditService(db *gorm.DB, logger *zap.Logger, cfg *config.Config) *AuditService {
	return &AuditService{
		db:     db,
		logger: logger,
		config: cfg,
	}
}

func (s *AuditService) ListAuditLogs(ctx context.Context, realmName string, req *models.AuditLogSearchRequest) ([]models.AuditLog, int64, error) {
	var logs []models.AuditLog
	var total int64

	query := s.db.WithContext(ctx).Model(&models.AuditLog{}).Where("realm_name = ?", realmName)

	if req.KeycloakUserID != nil {
		query = query.Where("keycloak_user_id = ?", *req.KeycloakUserID)
	}

	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}

	if req.ResourceType != "" {
		query = query.Where("resource_type = ?", req.ResourceType)
	}

	if req.ResourceID != "" {
		query = query.Where("resource_id = ?", req.ResourceID)
	}

	if req.Severity != nil {
		query = query.Where("severity = ?", *req.Severity)
	}

	if req.Status != nil {
		query = query.Where("status = ?", *req.Status)
	}

	if req.IPAddress != "" {
		query = query.Where("ip_address = ?", req.IPAddress)
	}

	if req.DateFrom != nil {
		query = query.Where("created_at >= ?", *req.DateFrom)
	}

	if req.DateTo != nil {
		query = query.Where("created_at <= ?", *req.DateTo)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	offset := (req.Page - 1) * req.PageSize
	orderBy := "created_at DESC"
	if req.SortBy != "" {
		order := "ASC"
		if req.SortOrder == "desc" {
			order = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", req.SortBy, order)
	}

	if err := query.Order(orderBy).Offset(offset).Limit(req.PageSize).Find(&logs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}

	return logs, total, nil
}

func (s *AuditService) GetAuditLog(ctx context.Context, realmName, logID string) (*models.AuditLog, error) {
	var log models.AuditLog
	if err := s.db.WithContext(ctx).Where("id = ? AND realm_name = ?", logID, realmName).First(&log).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	return &log, nil
}

func (s *AuditService) CreateAuditLog(ctx context.Context, realmName string, req *models.CreateAuditLogRequest) (*models.AuditLog, error) {
	log := &models.AuditLog{
		RealmName:      realmName,
		KeycloakUserID: req.KeycloakUserID,
		Action:       req.Action,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Details:      req.Details,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		SessionID:    req.SessionID,
		Severity:     req.Severity,
		Status:       req.Status,
	}

	if err := s.db.WithContext(ctx).Create(log).Error; err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	return log, nil
}

func (s *AuditService) GetAuditStats(ctx context.Context, realmName string, from, to time.Time) (*models.AuditLogStatsResponse, error) {
	stats := &models.AuditLogStatsResponse{
		SeverityBreakdown: make(map[models.AuditSeverity]int64),
		StatusBreakdown:   make(map[models.AuditStatus]int64),
	}

	query := s.db.WithContext(ctx).Model(&models.AuditLog{}).Where("realm_name = ?", realmName)
	if !from.IsZero() {
		query = query.Where("created_at >= ?", from)
	}
	if !to.IsZero() {
		query = query.Where("created_at <= ?", to)
	}

	if err := query.Count(&stats.TotalEvents).Error; err != nil {
		return nil, fmt.Errorf("failed to count total events: %w", err)
	}

	var securityCount int64
	if err := query.Where("action LIKE 'user.login%' OR action LIKE 'user.logout%' OR action LIKE 'role.%' OR action LIKE 'sso.%' OR severity IN ('error', 'critical')").Count(&securityCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count security events: %w", err)
	}
	stats.SecurityEvents = securityCount

	var failedCount int64
	if err := query.Where("status = 'failure'").Count(&failedCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count failed events: %w", err)
	}
	stats.FailedEvents = failedCount

	var recentCount int64
	recentTime := time.Now().Add(-24 * time.Hour)
	if err := query.Where("created_at >= ?", recentTime).Count(&recentCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count recent events: %w", err)
	}
	stats.RecentEvents = recentCount

	return stats, nil
}
