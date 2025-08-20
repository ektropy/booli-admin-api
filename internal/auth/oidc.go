package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	DefaultAzureADAuthority = "https://login.microsoftonline.com"
	AzureADUSGovAuthority   = "https://login.microsoftonline.us"
	AzureADChinaAuthority   = "https://login.chinacloudapi.cn"
	AzureADV2Suffix         = "v2.0"
)

type AzureADEndpoints struct {
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
	IssuerURL        string
	JWKSURL          string
}

func buildAzureADIssuerURL(authority, tenantID string) string {
	if authority == "" {
		authority = os.Getenv("AZURE_AD_AUTHORITY")
		if authority == "" {
			authority = DefaultAzureADAuthority
		}
	}
	
	authority = strings.TrimRight(authority, "/")
	tenantID = strings.Trim(tenantID, "/")
	
	return fmt.Sprintf("%s/%s/%s", authority, tenantID, AzureADV2Suffix)
}

func BuildAzureADEndpoints(authority, tenantID string) *AzureADEndpoints {
	if authority == "" {
		authority = os.Getenv("AZURE_AD_AUTHORITY")
		if authority == "" {
			authority = DefaultAzureADAuthority
		}
	}
	
	authority = strings.TrimRight(authority, "/")
	tenantID = strings.Trim(tenantID, "/")
	base := fmt.Sprintf("%s/%s", authority, tenantID)
	
	return &AzureADEndpoints{
		AuthorizationURL: fmt.Sprintf("%s/oauth2/v2.0/authorize", base),
		TokenURL:         fmt.Sprintf("%s/oauth2/v2.0/token", base),
		UserInfoURL:      fmt.Sprintf("%s/openid/userinfo", base),
		IssuerURL:        fmt.Sprintf("%s/v2.0", base),
		JWKSURL:          fmt.Sprintf("%s/discovery/v2.0/keys", base),
	}
}

type OIDCProvider struct {
	Name                string
	IssuerURL           string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	RealmName           string
	APIAudience         string
	SkipTLSVerify       bool
	CACertPath          string
	provider            *oidc.Provider
	oauth2Config        *oauth2.Config
	verifier            *oidc.IDTokenVerifier
	accessTokenVerifier *oidc.IDTokenVerifier
	logger              *zap.Logger
}

type OIDCService struct {
	providers map[string]*OIDCProvider
	logger    *zap.Logger
}

type OIDCClaims struct {
	Subject           string `json:"sub"`
	Issuer            string `json:"iss"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`

	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	Roles         []string `json:"roles"`
	Groups        []string `json:"groups"`

	Organizations []string `json:"organizations,omitempty"`
	ActiveOrg     string   `json:"active_org,omitempty"`
}

func NewOIDCService(logger *zap.Logger) *OIDCService {
	return &OIDCService{
		providers: make(map[string]*OIDCProvider),
		logger:    logger,
	}
}

func (s *OIDCService) AddProvider(ctx context.Context, config *OIDCProvider) error {
	return s.addStandardOIDCProvider(ctx, config)
}

func (s *OIDCService) addStandardOIDCProvider(ctx context.Context, config *OIDCProvider) error {
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider %s: %w", config.Name, err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, config.Scopes...),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	accessTokenVerifier := provider.Verifier(&oidc.Config{
		ClientID:          config.APIAudience,
		SkipIssuerCheck:   true,
		SkipClientIDCheck: true,
	})

	config.provider = provider
	config.oauth2Config = oauth2Config
	config.verifier = verifier
	config.accessTokenVerifier = accessTokenVerifier
	config.logger = s.logger

	s.providers[config.Name] = config

	s.logger.Info("OIDC provider added successfully",
		zap.String("provider", config.Name),
		zap.String("issuer", config.IssuerURL))

	return nil
}


func (s *OIDCService) GetProvider(name string) (*OIDCProvider, error) {
	provider, exists := s.providers[name]
	if !exists {
		return nil, fmt.Errorf("OIDC provider '%s' not found", name)
	}
	return provider, nil
}

func (p *OIDCProvider) GenerateAuthURL(state string) string {
	if state == "" {
		state = generateRandomState()
	}

	return p.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (p *OIDCProvider) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

func (p *OIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (*OIDCClaims, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}


	return &claims, nil
}

func (p *OIDCProvider) VerifyAccessTokenAsJWT(ctx context.Context, accessToken string) (*OIDCClaims, error) {
	token, err := p.accessTokenVerifier.Verify(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token as JWT: %w", err)
	}

	var claims OIDCClaims
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}


	return &claims, nil
}

func (p *OIDCProvider) VerifyAccessToken(ctx context.Context, accessToken string) (*OIDCClaims, error) {
	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	var claims OIDCClaims
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract user info claims: %w", err)
	}

	return &claims, nil
}


func (p *OIDCProvider) GetWellKnownConfig(ctx context.Context) (map[string]interface{}, error) {
	transport := &http.Transport{}
	if p.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- User explicitly configured to skip TLS verification
			MinVersion:         tls.VersionTLS12,
		}
	} else if p.CACertPath != "" {
		caCert, err := os.ReadFile(filepath.Clean(p.CACertPath))
		if err == nil {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				transport.TLSClientConfig = &tls.Config{
					RootCAs:    caCertPool,
					MinVersion: tls.VersionTLS12,
				}
			}
		}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-configuration",
		strings.TrimSuffix(p.IssuerURL, "/"))

	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("well-known endpoint returned status %d", resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse well-known config: %w", err)
	}

	return config, nil
}

func (s *OIDCService) ValidateToken(ctx context.Context, providerName, token string) (*OIDCClaims, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	claims, err := provider.VerifyAccessTokenAsJWT(ctx, token)
	if err != nil {
		s.logger.Debug("Access token JWT verification failed, trying ID token",
			zap.Error(err))

		claims, err = provider.VerifyIDToken(ctx, token)
		if err != nil {
			s.logger.Debug("ID token verification failed, trying UserInfo endpoint",
				zap.Error(err))

			claims, err = provider.VerifyAccessToken(ctx, token)
			if err != nil {
				return nil, fmt.Errorf("token verification failed: %w", err)
			}
		}
	}

	return claims, nil
}

func (s *OIDCService) GetProviderNames() []string {
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	return names
}

func generateRandomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random state: %v", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

func CreateKeycloakProvider(name, baseURL, realm, clientID, clientSecret, redirectURL, apiAudience string, skipTLSVerify bool, caCertPath string) *OIDCProvider {
	issuerURL := fmt.Sprintf("%s/realms/%s", strings.TrimSuffix(baseURL, "/"), realm)

	return &OIDCProvider{
		Name:          name,
		IssuerURL:     issuerURL,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RedirectURL:   redirectURL,
		Scopes:        []string{"openid", "profile", "email", "roles"},
		APIAudience:   apiAudience,
		RealmName:     realm,
		SkipTLSVerify: skipTLSVerify,
		CACertPath:    caCertPath,
	}
}

func CreateKeycloakMSPProvider(baseURL, mspRealm, clientID, clientSecret, redirectURL, apiAudience string, skipTLSVerify bool, caCertPath string) *OIDCProvider {
	return CreateKeycloakProvider(
		fmt.Sprintf("keycloak-%s", mspRealm),
		baseURL,
		mspRealm,
		clientID,
		clientSecret,
		redirectURL,
		apiAudience,
		skipTLSVerify,
		caCertPath,
	)
}


func (p *OIDCProvider) GetClientCredentialsToken(ctx context.Context, scopes []string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}

	token, err := config.Exchange(ctx, "", oauth2.SetAuthURLParam("grant_type", "client_credentials"))
	if err != nil {
		return nil, fmt.Errorf("failed to get client credentials token: %w", err)
	}

	return token, nil
}

func (s *OIDCService) ValidateServiceToken(ctx context.Context, providerName, accessToken string) (*OIDCClaims, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	claims, err := provider.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("service token verification failed: %w", err)
	}

	return claims, nil
}
