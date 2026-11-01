package trustclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const oidcExchangePath = "/rest/api/v1/oidc/exchange"

// ExchangeResult is the result of POST /rest/api/v1/oidc/exchange.
// TokenID is the value to send as x-api-token.
type ExchangeResult struct {
	TokenID     string
	ExpiresAt   *Time
	TokenType   string
	AccountID   string
	PrincipalID string
}

type exchangeBody struct {
	IDTokenSnake   string `json:"id_token"`
	IDTokenCamel   string `json:"idToken"`
	TokenTypeSnake string `json:"token_type,omitempty"`
	TokenTypeCamel string `json:"tokenType,omitempty"`
}

// ExchangeIDToken exchanges an OIDC id token for a short-lived Trust token.
// An empty tokenType uses the matched principal's default mint type.
// SECRET, CERTIFICATE, and MCP are the types the Gateway accepts.
func ExchangeIDToken(ctx context.Context, trustURL, idToken string, tokenType TokenType) (ExchangeResult, error) {
	if strings.TrimSpace(trustURL) == "" {
		return ExchangeResult{}, trustErr("trustUrl is required")
	}
	if strings.TrimSpace(idToken) == "" {
		return ExchangeResult{}, trustErr("idToken is required")
	}
	if err := validateMintType(tokenType); err != nil {
		return ExchangeResult{}, err
	}
	if err := validateBaseURL(strings.TrimSpace(trustURL)); err != nil {
		return ExchangeResult{}, err
	}
	payload := exchangeBody{
		IDTokenSnake: idToken,
		IDTokenCamel: idToken,
	}
	if tokenType != "" {
		payload.TokenTypeSnake = string(tokenType)
		payload.TokenTypeCamel = string(tokenType)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ExchangeResult{}, wrapErr("OIDC exchange failed: "+err.Error(), err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(strings.TrimSpace(trustURL), "/") + oidcExchangePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ExchangeResult{}, wrapErr("OIDC exchange failed: "+err.Error(), err)
	}
	req.Header.Set("Content-Type", mediaJSON)
	req.Header.Set("Accept", mediaJSON)

	client := newSimpleClient(DefaultConnectTimeout)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return ExchangeResult{}, wrapErr("OIDC exchange failed: "+err.Error(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExchangeResult{}, wrapErr("OIDC exchange failed: "+err.Error(), err)
	}
	if resp.StatusCode != http.StatusOK {
		return ExchangeResult{}, trustErrf("OIDC exchange failed: HTTP %d body=%s", resp.StatusCode, truncate(string(body), 300))
	}
	return parseExchange(body)
}

func parseExchange(body []byte) (ExchangeResult, error) {
	if strings.TrimSpace(string(body)) == "" {
		return ExchangeResult{}, trustErr("OIDC exchange returned empty body")
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return ExchangeResult{}, wrapErr("OIDC exchange failed: "+err.Error(), err)
	}
	if msg := stringField(root, "errorMessage", "error_message"); msg != "" {
		return ExchangeResult{}, trustErr("OIDC exchange denied: " + msg)
	}
	tokenID := stringField(root, "tokenId", "token_id")
	if tokenID == "" {
		return ExchangeResult{}, trustErr("OIDC exchange response missing tokenId")
	}
	result := ExchangeResult{
		TokenID:     tokenID,
		TokenType:   stringField(root, "tokenType", "token_type"),
		AccountID:   stringField(root, "accountId", "account_id"),
		PrincipalID: stringField(root, "principalId", "principal_id"),
	}
	if exp := stringField(root, "expiresAt", "expires_at"); exp != "" {
		if ts, err := parseTrustTime(exp); err == nil && !ts.IsZero() {
			result.ExpiresAt = &Time{Time: ts}
		}
	}
	return result, nil
}

func validateMintType(tokenType TokenType) error {
	switch tokenType {
	case "", TokenTypeSecret, TokenTypeCertificate, TokenTypeMCP:
		return nil
	default:
		return trustErrf("OIDC exchange tokenType must be SECRET, CERTIFICATE, or MCP (got %s)", tokenType)
	}
}

// ExchangeGitHubActions requests a GitHub Actions OIDC token and exchanges it.
func ExchangeGitHubActions(ctx context.Context, trustURL, audience string, tokenType TokenType) (ExchangeResult, error) {
	jwt, err := RequestGitHubActionsIDToken(ctx, audience)
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeIDToken(ctx, trustURL, jwt, tokenType)
}

// ExchangeGCP requests a GCP identity token and exchanges it.
func ExchangeGCP(ctx context.Context, trustURL, audience string, tokenType TokenType) (ExchangeResult, error) {
	jwt, err := RequestGCPIDToken(ctx, audience)
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeIDToken(ctx, trustURL, jwt, tokenType)
}

// ExchangeAzure requests an Azure managed-identity token and exchanges it.
func ExchangeAzure(ctx context.Context, trustURL, audience string, tokenType TokenType) (ExchangeResult, error) {
	jwt, err := RequestAzureIDToken(ctx, audience)
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeIDToken(ctx, trustURL, jwt, tokenType)
}

// ExchangeAzureDevOps requests an Azure DevOps OIDC token and exchanges it.
// Azure DevOps tokens use the fixed audience api://AzureADTokenExchange.
func ExchangeAzureDevOps(ctx context.Context, trustURL string, tokenType TokenType) (ExchangeResult, error) {
	jwt, err := RequestAzureDevOpsIDToken(ctx)
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeIDToken(ctx, trustURL, jwt, tokenType)
}

// ExchangeDeviceOIDC mints a device JWT and exchanges it.
func ExchangeDeviceOIDC(ctx context.Context, trustURL string, cfg DeviceOIDCConfig, tokenType TokenType) (ExchangeResult, error) {
	jwt, err := MintDeviceJWT(cfg)
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeIDToken(ctx, trustURL, jwt, tokenType)
}

func truncate(s string, n int) string {
	if s == "" {
		return ""
	}
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func nonBlank(s string) bool {
	return strings.TrimSpace(s) != ""
}
