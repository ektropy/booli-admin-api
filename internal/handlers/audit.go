package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

type AuditServiceInterface interface {
	ListAuditLogs(ctx context.Context, realmName string, req *models.AuditLogSearchRequest) ([]models.AuditLog, int64, error)
	GetAuditLog(ctx context.Context, realmName, logID string) (*models.AuditLog, error)
	CreateAuditLog(ctx context.Context, realmName string, req *models.CreateAuditLogRequest) (*models.AuditLog, error)
	GetAuditStats(ctx context.Context, realmName string, from, to time.Time) (*models.AuditLogStatsResponse, error)
}

type AuditHandler struct {
	auditService AuditServiceInterface
	logger       *zap.Logger
	validator    *validator.Validate
}

func NewAuditHandler(auditService AuditServiceInterface, logger *zap.Logger) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
		logger:       logger,
		validator:    validator.New(),
	}
}

// @Summary List audit logs
// @Description Get paginated list of audit logs
// @Tags audit
// @Produce json
// @Param start_date query string false "Start date"
// @Param end_date query string false "End date"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /audit/logs [get]
func (h *AuditHandler) List(c *gin.Context) {
	realmName, exists := c.Get("realm_name")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "realm_name not found in context", nil)
		return
	}

	var req models.AuditLogSearchRequest
	req.Page = 1
	req.PageSize = 50

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			req.Page = parsed
		}
	}

	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 1000 {
			req.PageSize = parsed
		}
	}

	if keycloakUserID := c.Query("keycloak_user_id"); keycloakUserID != "" {
		req.KeycloakUserID = &keycloakUserID
	}

	if action := c.Query("action"); action != "" {
		req.Action = action
	}

	if resourceType := c.Query("resource_type"); resourceType != "" {
		req.ResourceType = resourceType
	}

	if resourceID := c.Query("resource_id"); resourceID != "" {
		req.ResourceID = resourceID
	}

	if severity := c.Query("severity"); severity != "" {
		auditSeverity := models.AuditSeverity(severity)
		req.Severity = &auditSeverity
	}

	if status := c.Query("status"); status != "" {
		auditStatus := models.AuditStatus(status)
		req.Status = &auditStatus
	}

	if ipAddress := c.Query("ip_address"); ipAddress != "" {
		req.IPAddress = ipAddress
	}

	if dateFrom := c.Query("date_from"); dateFrom != "" {
		if parsed, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			req.DateFrom = &parsed
		}
	}

	if dateTo := c.Query("date_to"); dateTo != "" {
		if parsed, err := time.Parse(time.RFC3339, dateTo); err == nil {
			req.DateTo = &parsed
		}
	}

	req.SortBy = c.Query("sort_by")
	req.SortOrder = c.Query("sort_order")

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed, "Validation failed", utils.FormatValidationErrors(err))
		return
	}

	logs, total, err := h.auditService.ListAuditLogs(c.Request.Context(), realmName.(string), &req)
	if err != nil {
		h.logger.Error("Failed to list audit logs", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list audit logs", nil)
		return
	}

	response := &models.AuditLogListResponse{
		Logs:       make([]models.AuditLogResponse, len(logs)),
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: int((total + int64(req.PageSize) - 1) / int64(req.PageSize)),
	}

	for i, log := range logs {
		response.Logs[i] = *log.ToResponse()
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get audit log
// @Description Get audit log by ID
// @Tags audit
// @Produce json
// @Param id path string true "Audit log ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /audit/logs/{id} [get]
func (h *AuditHandler) Get(c *gin.Context) {
	realmName, exists := c.Get("realm_name")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "realm_name not found in context", nil)
		return
	}

	logID := c.Param("id")
	if logID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Log ID is required", nil)
		return
	}

	log, err := h.auditService.GetAuditLog(c.Request.Context(), realmName.(string), logID)
	if err != nil {
		h.logger.Error("Failed to get audit log", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get audit log", nil)
		return
	}

	if log == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Audit log not found", nil)
		return
	}

	c.JSON(http.StatusOK, log.ToResponse())
}

// @Summary Export audit logs
// @Description Export audit logs to various formats
// @Tags audit
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /audit/export [post]
func (h *AuditHandler) Export(c *gin.Context) {
	realmName, exists := c.Get("realm_name")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "realm_name not found in context", nil)
		return
	}

	format := c.Query("format")
	if format == "" {
		format = "csv"
	}

	var req models.AuditLogSearchRequest
	req.Page = 1
	req.PageSize = 10000

	if keycloakUserID := c.Query("keycloak_user_id"); keycloakUserID != "" {
		req.KeycloakUserID = &keycloakUserID
	}

	if action := c.Query("action"); action != "" {
		req.Action = action
	}

	if resourceType := c.Query("resource_type"); resourceType != "" {
		req.ResourceType = resourceType
	}

	if severity := c.Query("severity"); severity != "" {
		auditSeverity := models.AuditSeverity(severity)
		req.Severity = &auditSeverity
	}

	if status := c.Query("status"); status != "" {
		auditStatus := models.AuditStatus(status)
		req.Status = &auditStatus
	}

	if dateFrom := c.Query("date_from"); dateFrom != "" {
		if parsed, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			req.DateFrom = &parsed
		}
	}

	if dateTo := c.Query("date_to"); dateTo != "" {
		if parsed, err := time.Parse(time.RFC3339, dateTo); err == nil {
			req.DateTo = &parsed
		}
	}

	logs, _, err := h.auditService.ListAuditLogs(c.Request.Context(), realmName.(string), &req)
	if err != nil {
		h.logger.Error("Failed to list audit logs for export", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to export audit logs", nil)
		return
	}

	switch format {
	case "csv":
		h.exportCSV(c, logs)
	case "json":
		h.exportJSON(c, logs)
	default:
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Unsupported format. Use 'csv' or 'json'", nil)
	}
}

func (h *AuditHandler) exportCSV(c *gin.Context, logs []models.AuditLog) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	header := []string{"ID", "Keycloak User ID", "User Email", "Action", "Resource Type", "Resource ID", "IP Address", "Severity", "Status", "Created At"}
	_ = writer.Write(header)

	for _, log := range logs {
		userEmail := ""
		keycloakUserIDStr := ""
		if log.KeycloakUserID != nil {
			keycloakUserIDStr = *log.KeycloakUserID
		}

		record := []string{
			log.ID,
			keycloakUserIDStr,
			userEmail,
			log.Action,
			log.ResourceType,
			log.ResourceID,
			log.IPAddress,
			string(log.Severity),
			string(log.Status),
			log.CreatedAt.Format(time.RFC3339),
		}
		_ = writer.Write(record)
	}

	writer.Flush()

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit-logs-export-%s.csv", time.Now().Format("2006-01-02")))
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func (h *AuditHandler) exportJSON(c *gin.Context, logs []models.AuditLog) {
	responses := make([]models.AuditLogResponse, len(logs))
	for i, log := range logs {
		responses[i] = *log.ToResponse()
	}

	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit-logs-export-%s.json", time.Now().Format("2006-01-02")))
	c.JSON(http.StatusOK, gin.H{"logs": responses})
}
