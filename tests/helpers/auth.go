package helpers

import (
	"context"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/constants"
	"go.uber.org/zap"
)

func SetupTestOIDCProviders(oidcService *auth.OIDCService, keycloakURL, callbackURL string, logger *zap.Logger) error {
	if callbackURL == "" {
		callbackURL = "http://localhost:8081" + constants.PathAuthCallback
	}

	mspProvider := auth.CreateKeycloakProvider(
		"keycloak",
		keycloakURL,
		"msp",
		"msp-client",
		"msp-secret",
		callbackURL,
		"booli-admin-api",
		false,
		"",
	)

	if err := oidcService.AddProvider(context.Background(), mspProvider); err != nil {
		logger.Debug("Failed to add MSP platform OIDC provider", zap.Error(err))
		return err
	}

	return nil
}
