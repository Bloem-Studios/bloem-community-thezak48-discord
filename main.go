package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultDiscordBaseURL = "https://discord.com"
	defaultScopes         = "identify email"
	httpTimeout           = 15 * time.Second
)

// version is set at build time via -ldflags "-X main.version=...".
var version string

//go:embed manifest.json
var manifestJSON []byte

type pluginConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
	Scopes       string
}

type runtimeServer struct {
	runtimedefault.Server
	manifest *pluginv1.PluginManifest

	mu     sync.RWMutex
	config pluginConfig
}

type authServer struct {
	pluginv1.UnimplementedAuthProviderServer
	runtime *runtimeServer
	client  *http.Client
}

type discordTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	GlobalName    string `json:"global_name"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	Locale        string `json:"locale"`
	Avatar        string `json:"avatar"`
	Discriminator string `json:"discriminator"`
	MFAEnabled    bool   `json:"mfa_enabled"`
}

func (s *runtimeServer) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{Manifest: s.manifest}, nil
}

func (s *runtimeServer) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "configure request is required")
	}
	cfg, err := configFromEntries(req.GetConfig())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()

	return &pluginv1.ConfigureResponse{}, nil
}

func (s *runtimeServer) currentConfig() pluginConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *authServer) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "password auth is not supported; use oauth2")
}

func (s *authServer) InitAuthorize(_ context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	cfg, err := s.requireConfigured()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetRedirectUri()) == "" {
		return nil, status.Error(codes.InvalidArgument, "redirect_uri is required")
	}
	if strings.TrimSpace(req.GetState()) == "" {
		return nil, status.Error(codes.InvalidArgument, "state is required")
	}

	authorizeURL, err := withPath(cfg.BaseURL, "/oauth2/authorize")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build authorize URL: %v", err)
	}

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", cfg.ClientID)
	values.Set("redirect_uri", req.GetRedirectUri())
	values.Set("scope", cfg.Scopes)
	values.Set("state", req.GetState())
	values.Set("prompt", "consent")

	out := authorizeURL + "?" + values.Encode()
	providerState, _ := structpb.NewStruct(map[string]any{"scope": cfg.Scopes})
	return &pluginv1.InitAuthorizeResponse{
		AuthorizeUrl:  out,
		ProviderState: providerState,
	}, nil
}

func (s *authServer) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	cfg, err := s.requireConfigured()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetCode()) == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	if strings.TrimSpace(req.GetRedirectUri()) == "" {
		return nil, status.Error(codes.InvalidArgument, "redirect_uri is required")
	}

	token, err := s.exchangeCode(ctx, cfg, req.GetCode(), req.GetRedirectUri())
	if err != nil {
		return nil, err
	}
	user, err := s.fetchUser(ctx, cfg, token.AccessToken)
	if err != nil {
		return nil, err
	}
	return authResponseFromDiscord(user, token), nil
}

func (s *authServer) RefreshSession(ctx context.Context, req *pluginv1.RefreshSessionRequest) (*pluginv1.AuthenticateResponse, error) {
	cfg, err := s.requireConfigured()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetExternalSubject()) == "" {
		return nil, status.Error(codes.InvalidArgument, "external_subject is required")
	}

	refreshToken := refreshTokenFromStruct(req.GetRefreshState())
	if refreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_state.refresh_token is required")
	}

	token, err := s.refreshToken(ctx, cfg, refreshToken)
	if err != nil {
		return nil, err
	}
	user, err := s.fetchUser(ctx, cfg, token.AccessToken)
	if err != nil {
		return nil, err
	}
	if user.ID != req.GetExternalSubject() {
		return nil, status.Error(codes.PermissionDenied, "refresh token subject mismatch")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	return authResponseFromDiscord(user, token), nil
}

func (s *authServer) requireConfigured() (pluginConfig, error) {
	cfg := s.runtime.currentConfig()
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return pluginConfig{}, status.Error(codes.FailedPrecondition, "plugin is not configured with discord_client_id and discord_client_secret")
	}
	return cfg, nil
}

func (s *authServer) exchangeCode(ctx context.Context, cfg pluginConfig, code, redirectURI string) (*discordTokenResponse, error) {
	tokenURL, err := withPath(cfg.BaseURL, "/api/oauth2/token")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build token URL: %v", err)
	}

	values := url.Values{}
	values.Set("client_id", cfg.ClientID)
	values.Set("client_secret", cfg.ClientSecret)
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("redirect_uri", redirectURI)

	return s.tokenRequest(ctx, tokenURL, values)
}

func (s *authServer) refreshToken(ctx context.Context, cfg pluginConfig, refreshToken string) (*discordTokenResponse, error) {
	tokenURL, err := withPath(cfg.BaseURL, "/api/oauth2/token")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build token URL: %v", err)
	}

	values := url.Values{}
	values.Set("client_id", cfg.ClientID)
	values.Set("client_secret", cfg.ClientSecret)
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", refreshToken)

	return s.tokenRequest(ctx, tokenURL, values)
}

func (s *authServer) tokenRequest(ctx context.Context, tokenURL string, values url.Values) (*discordTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "token request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read token response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, status.Errorf(codes.Unauthenticated, "token exchange failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var token discordTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, status.Errorf(codes.Internal, "decode token response: %v", err)
	}
	if token.AccessToken == "" {
		return nil, status.Error(codes.Unauthenticated, "token response missing access_token")
	}
	return &token, nil
}

func (s *authServer) fetchUser(ctx context.Context, cfg pluginConfig, accessToken string) (*discordUser, error) {
	userURL, err := withPath(cfg.BaseURL, "/api/users/@me")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build user URL: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create user request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "user request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read user response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, status.Errorf(codes.Unauthenticated, "fetch user failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var user discordUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, status.Errorf(codes.Internal, "decode user response: %v", err)
	}
	if user.ID == "" {
		return nil, status.Error(codes.Unauthenticated, "discord user response missing id")
	}
	return &user, nil
}

func authResponseFromDiscord(user *discordUser, token *discordTokenResponse) *pluginv1.AuthenticateResponse {
	displayName := strings.TrimSpace(user.GlobalName)
	if displayName == "" {
		displayName = strings.TrimSpace(user.Username)
	}

	claimsMap := map[string]any{
		"provider":       "discord",
		"discord_id":     user.ID,
		"username":       user.Username,
		"global_name":    user.GlobalName,
		"avatar":         user.Avatar,
		"discriminator":  user.Discriminator,
		"locale":         user.Locale,
		"verified":       user.Verified,
		"mfa_enabled":    user.MFAEnabled,
		"email_verified": user.Verified,
		"refresh_state": map[string]any{
			"refresh_token": token.RefreshToken,
			"scope":         token.Scope,
		},
	}
	claims, _ := structpb.NewStruct(claimsMap)

	return &pluginv1.AuthenticateResponse{
		ExternalSubject: user.ID,
		DisplayName:     displayName,
		Email:           strings.TrimSpace(user.Email),
		Claims:          claims,
	}
}

func configFromEntries(entries []*pluginv1.ConfigEntry) (pluginConfig, error) {
	cfg := pluginConfig{
		BaseURL: defaultDiscordBaseURL,
		Scopes:  defaultScopes,
	}
	cfg.ClientID = entryString(entries, "discord_client_id")
	cfg.ClientSecret = entryString(entries, "discord_client_secret")
	if baseURL := entryString(entries, "discord_base_url"); baseURL != "" {
		cfg.BaseURL = baseURL
	}
	if scopes := entryString(entries, "discord_scopes"); scopes != "" {
		cfg.Scopes = scopes
	}

	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Scopes = strings.Join(strings.Fields(cfg.Scopes), " ")
	if cfg.Scopes == "" {
		cfg.Scopes = defaultScopes
	}
	if _, err := url.ParseRequestURI(cfg.BaseURL); err != nil {
		return pluginConfig{}, status.Errorf(codes.InvalidArgument, "discord_base_url is invalid: %v", err)
	}

	return cfg, nil
}

func entryString(entries []*pluginv1.ConfigEntry, key string) string {
	for _, entry := range entries {
		if entry == nil || entry.GetKey() != key || entry.GetValue() == nil {
			continue
		}

		asMap := entry.GetValue().AsMap()
		if raw, ok := asMap["value"]; ok {
			if str, ok := raw.(string); ok {
				return strings.TrimSpace(str)
			}
		}
		if raw, ok := asMap[key]; ok {
			if str, ok := raw.(string); ok {
				return strings.TrimSpace(str)
			}
		}
	}
	return ""
}

func refreshTokenFromStruct(v *structpb.Struct) string {
	if v == nil {
		return ""
	}
	asMap := v.AsMap()
	if token, ok := asMap["refresh_token"].(string); ok && strings.TrimSpace(token) != "" {
		return strings.TrimSpace(token)
	}
	nested, ok := asMap["refresh_state"].(map[string]any)
	if !ok {
		return ""
	}
	token, _ := nested["refresh_token"].(string)
	return strings.TrimSpace(token)
}

func withPath(baseURL, targetPath string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(targetPath)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func loadManifest() (*pluginv1.PluginManifest, error) {
	manifest, err := publicmanifest.Load(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("load embedded manifest: %w", err)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	binaryData, err := os.ReadFile(executablePath)
	if err != nil {
		return nil, fmt.Errorf("read executable %q: %w", executablePath, err)
	}
	checksum := sha256.Sum256(binaryData)
	manifest.Checksum = hex.EncodeToString(checksum[:])
	if version != "" {
		manifest.Version = version
	}
	return manifest, nil
}

func main() {
	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}

	runtimeSrv := &runtimeServer{
		manifest: manifest,
		config: pluginConfig{
			BaseURL: defaultDiscordBaseURL,
			Scopes:  defaultScopes,
		},
	}

	authSrv := &authServer{
		runtime: runtimeSrv,
		client:  &http.Client{Timeout: httpTimeout},
	}

	runtime.Serve(runtime.ServeConfig{
		Servers: runtime.CapabilityServers{
			Runtime:      runtimeSrv,
			AuthProvider: authSrv,
		},
	})
}
