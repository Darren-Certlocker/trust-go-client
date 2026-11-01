package trustclient

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// GitHubActionsRequestURLEnv is the GitHub Actions OIDC request URL.
	GitHubActionsRequestURLEnv = "ACTIONS_ID_TOKEN_REQUEST_URL"
	// GitHubActionsRequestTokenEnv is the bearer token for the OIDC request URL.
	GitHubActionsRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// GCPMetadataHostEnv overrides the GCE metadata host.
	GCPMetadataHostEnv = "GCE_METADATA_HOST"
	// GCPCloudRunServiceEnv is set on Cloud Run.
	GCPCloudRunServiceEnv = "K_SERVICE"
	gcpMetadataHost       = "metadata.google.internal"
	gcpIdentityPath       = "/computeMetadata/v1/instance/service-accounts/default/identity"

	// AzureIdentityEndpointEnv is the App Service / Functions identity endpoint.
	AzureIdentityEndpointEnv = "IDENTITY_ENDPOINT"
	// AzureIdentityHeaderEnv is the header secret paired with the identity endpoint.
	AzureIdentityHeaderEnv = "IDENTITY_HEADER"
	// AzureClientIDEnv selects a user-assigned identity when several are present.
	AzureClientIDEnv = "AZURE_CLIENT_ID"
	azureIMDSBase    = "http://169.254.169.254"
	azureIMDSPath    = "/metadata/identity/oauth2/token"
	azureIMDSVersion = "2018-02-01"
	azureAppVersion  = "2019-08-01"

	// AzureDevOpsRequestURIEnv is the Azure Pipelines OIDC request URI.
	AzureDevOpsRequestURIEnv = "SYSTEM_OIDCREQUESTURI"
	// AzureDevOpsAccessTokenEnv is the bearer for the OIDC request.
	AzureDevOpsAccessTokenEnv = "SYSTEM_ACCESSTOKEN"
	// AzureDevOpsServiceConnectionEnv is the AzureRM service connection id.
	AzureDevOpsServiceConnectionEnv = "AZURESUBSCRIPTION_SERVICE_CONNECTION_ID"
	// AzureDevOpsServiceConnectionAltEnv is an alternate service connection id.
	AzureDevOpsServiceConnectionAltEnv = "SYSTEM_OIDC_SERVICE_CONNECTION_ID"
)

// metadataProbeTimeout bounds GCP and Azure availability probes.
var metadataProbeTimeout = 250 * time.Millisecond

var (
	gcpMu    sync.Mutex
	gcpKnown bool
	gcpOK    bool

	azureMu    sync.Mutex
	azureKnown bool
	azureOK    bool
)

func resetMetadataCache() {
	gcpMu.Lock()
	gcpKnown = false
	gcpOK = false
	gcpMu.Unlock()
	azureMu.Lock()
	azureKnown = false
	azureOK = false
	azureMu.Unlock()
}

// GitHubActionsAvailable reports whether GitHub Actions OIDC request env is present.
func GitHubActionsAvailable() bool {
	return nonBlank(os.Getenv(GitHubActionsRequestURLEnv)) && nonBlank(os.Getenv(GitHubActionsRequestTokenEnv))
}

// RequestGitHubActionsIDToken fetches an ID token for audience.
// The workflow needs permissions: id-token: write.
func RequestGitHubActionsIDToken(ctx context.Context, audience string) (string, error) {
	if !nonBlank(audience) {
		return "", trustErr("OIDC audience is required")
	}
	requestURL := os.Getenv(GitHubActionsRequestURLEnv)
	requestToken := os.Getenv(GitHubActionsRequestTokenEnv)
	if !nonBlank(requestURL) || !nonBlank(requestToken) {
		return "", trustErr("GitHub Actions OIDC env not present (" +
			GitHubActionsRequestURLEnv + " / " + GitHubActionsRequestTokenEnv + ")")
	}
	sep := "?"
	if strings.Contains(requestURL, "?") {
		sep = "&"
	}
	endpoint := requestURL + sep + "audience=" + url.QueryEscape(strings.TrimSpace(audience))
	body, err := httpGET(ctx, endpoint, 30*time.Second, map[string]string{
		"Authorization": "Bearer " + requestToken,
		"Accept":        mediaJSON,
	})
	if err != nil {
		return "", wrapErr("GitHub OIDC token request failed: "+err.Error(), err)
	}
	if body.status != http.StatusOK {
		return "", trustErrf("GitHub OIDC token request failed: HTTP %d body=%s", body.status, truncate(body.text, 200))
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body.raw, &payload); err != nil || !nonBlank(payload.Value) {
		return "", trustErr("GitHub OIDC response missing value")
	}
	return payload.Value, nil
}

// GCPAvailable reports whether this process looks like it can reach the GCP metadata identity endpoint.
func GCPAvailable() bool {
	if nonBlank(os.Getenv(GCPCloudRunServiceEnv)) || nonBlank(os.Getenv(GCPMetadataHostEnv)) {
		return true
	}
	gcpMu.Lock()
	defer gcpMu.Unlock()
	if gcpKnown {
		return gcpOK
	}
	gcpOK = probeURL(metadataBase()+"/computeMetadata/v1/", "Metadata-Flavor", "Google")
	gcpKnown = true
	return gcpOK
}

// RequestGCPIDToken fetches a Google identity token for audience from the metadata server.
func RequestGCPIDToken(ctx context.Context, audience string) (string, error) {
	if !nonBlank(audience) {
		return "", trustErr("OIDC audience is required")
	}
	endpoint := metadataBase() + gcpIdentityPath +
		"?audience=" + url.QueryEscape(strings.TrimSpace(audience)) + "&format=full"
	body, err := httpGET(ctx, endpoint, 10*time.Second, map[string]string{
		"Metadata-Flavor": "Google",
	})
	if err != nil {
		return "", wrapErr("GCP identity token request failed: "+err.Error(), err)
	}
	if body.status != http.StatusOK {
		return "", trustErrf("GCP identity token request failed: HTTP %d body=%s", body.status, truncate(body.text, 200))
	}
	jwt := strings.TrimSpace(body.text)
	if jwt == "" {
		return "", trustErr("GCP identity token response empty")
	}
	return jwt, nil
}

func metadataBase() string {
	host := strings.TrimSpace(os.Getenv(GCPMetadataHostEnv))
	if host == "" {
		host = gcpMetadataHost
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/")
	}
	return "http://" + host
}

// AzureAvailable reports whether App Service identity env is set or IMDS answers a short probe.
func AzureAvailable() bool {
	if nonBlank(os.Getenv(AzureIdentityEndpointEnv)) && nonBlank(os.Getenv(AzureIdentityHeaderEnv)) {
		return true
	}
	azureMu.Lock()
	defer azureMu.Unlock()
	if azureKnown {
		return azureOK
	}
	azureOK = probeURL(azureIMDSBase+"/metadata/instance?api-version="+azureIMDSVersion, "Metadata", "true")
	azureKnown = true
	return azureOK
}

// RequestAzureIDToken fetches an Entra access token whose resource is audience.
func RequestAzureIDToken(ctx context.Context, audience string) (string, error) {
	if !nonBlank(audience) {
		return "", trustErr("OIDC audience is required")
	}
	endpoint := os.Getenv(AzureIdentityEndpointEnv)
	header := os.Getenv(AzureIdentityHeaderEnv)
	if nonBlank(endpoint) && nonBlank(header) {
		return requestAzureAppService(ctx, strings.TrimSpace(audience), strings.TrimSpace(endpoint), strings.TrimSpace(header))
	}
	return requestAzureIMDS(ctx, strings.TrimSpace(audience))
}

func requestAzureAppService(ctx context.Context, audience, endpoint, identityHeader string) (string, error) {
	q := "api-version=" + azureAppVersion + "&resource=" + url.QueryEscape(audience) + azureClientQuery()
	endpoint = appendQuery(endpoint, q)
	body, err := httpGET(ctx, endpoint, 10*time.Second, map[string]string{
		"X-IDENTITY-HEADER": identityHeader,
	})
	if err != nil {
		return "", wrapErr("Azure App Service identity token request failed: "+err.Error(), err)
	}
	return azureAccessToken(body, "Azure App Service identity")
}

func requestAzureIMDS(ctx context.Context, audience string) (string, error) {
	endpoint := azureIMDSBase + azureIMDSPath +
		"?api-version=" + azureIMDSVersion +
		"&resource=" + url.QueryEscape(audience) +
		azureClientQuery()
	body, err := httpGET(ctx, endpoint, 10*time.Second, map[string]string{
		"Metadata": "true",
	})
	if err != nil {
		return "", wrapErr("Azure IMDS identity token request failed: "+err.Error(), err)
	}
	return azureAccessToken(body, "Azure IMDS identity")
}

func azureAccessToken(body httpBody, label string) (string, error) {
	if body.status != http.StatusOK {
		return "", trustErrf("%s token request failed: HTTP %d body=%s", label, body.status, truncate(body.text, 200))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body.raw, &payload); err != nil || !nonBlank(payload.AccessToken) {
		if err != nil && len(bytesTrim(body.raw)) == 0 {
			return "", trustErr(label + " token response empty")
		}
		return "", trustErr(label + " response missing access_token")
	}
	return strings.TrimSpace(payload.AccessToken), nil
}

func azureClientQuery() string {
	clientID := os.Getenv(AzureClientIDEnv)
	if !nonBlank(clientID) {
		return ""
	}
	return "&client_id=" + url.QueryEscape(strings.TrimSpace(clientID))
}

func appendQuery(endpoint, query string) string {
	if strings.Contains(endpoint, "?") {
		return endpoint + "&" + query
	}
	return endpoint + "?" + query
}

// AzureDevOpsAvailable reports whether Azure DevOps OIDC request env is present.
func AzureDevOpsAvailable() bool {
	return nonBlank(os.Getenv(AzureDevOpsRequestURIEnv)) && nonBlank(os.Getenv(AzureDevOpsAccessTokenEnv))
}

// RequestAzureDevOpsIDToken fetches an Azure DevOps OIDC id token.
// The token audience is the fixed ADO value api://AzureADTokenExchange.
func RequestAzureDevOpsIDToken(ctx context.Context) (string, error) {
	requestURI := os.Getenv(AzureDevOpsRequestURIEnv)
	accessToken := os.Getenv(AzureDevOpsAccessTokenEnv)
	if !nonBlank(requestURI) || !nonBlank(accessToken) {
		return "", trustErr("Azure DevOps OIDC env not present (" +
			AzureDevOpsRequestURIEnv + " / " + AzureDevOpsAccessTokenEnv + ")")
	}
	sep := "?"
	if strings.Contains(requestURI, "?") {
		sep = "&"
	}
	endpoint := requestURI + sep + "api-version=" + url.QueryEscape("7.1")
	if id := firstNonBlank(os.Getenv(AzureDevOpsServiceConnectionEnv), os.Getenv(AzureDevOpsServiceConnectionAltEnv)); id != "" {
		endpoint += "&serviceConnectionId=" + url.QueryEscape(strings.TrimSpace(id))
	}
	body, err := httpPOST(ctx, endpoint, 30*time.Second, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  mediaJSON,
		"Accept":        mediaJSON,
	})
	if err != nil {
		return "", wrapErr("Azure DevOps OIDC token request failed: "+err.Error(), err)
	}
	if body.status < 200 || body.status >= 300 {
		return "", trustErrf("Azure DevOps OIDC token request failed: HTTP %d body=%s", body.status, truncate(body.text, 200))
	}
	var payload map[string]any
	if err := json.Unmarshal(body.raw, &payload); err != nil {
		return "", trustErr("Azure DevOps OIDC response empty")
	}
	token := stringField(payload, "oidcToken")
	if !nonBlank(token) {
		token = stringField(payload, "token")
	}
	if !nonBlank(token) {
		return "", trustErr("Azure DevOps OIDC response missing oidcToken")
	}
	return token, nil
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if nonBlank(v) {
			return v
		}
	}
	return ""
}

func bytesTrim(b []byte) string {
	return strings.TrimSpace(string(b))
}

type httpBody struct {
	status int
	raw    []byte
	text   string
}

func httpGET(ctx context.Context, endpoint string, timeout time.Duration, headers map[string]string) (httpBody, error) {
	return httpDo(ctx, http.MethodGet, endpoint, timeout, headers)
}

func httpPOST(ctx context.Context, endpoint string, timeout time.Duration, headers map[string]string) (httpBody, error) {
	return httpDo(ctx, http.MethodPost, endpoint, timeout, headers)
}

func httpDo(ctx context.Context, method, endpoint string, timeout time.Duration, headers map[string]string) (httpBody, error) {
	if ctx == nil {
		return httpBody{}, trustErr("context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if method == http.MethodPost {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return httpBody{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := newSimpleClient(DefaultConnectTimeout)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return httpBody{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpBody{}, err
	}
	return httpBody{status: resp.StatusCode, raw: raw, text: string(raw)}, nil
}

func probeURL(rawURL, header, value string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), metadataProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	if header != "" {
		req.Header.Set(header, value)
	}
	dialer := &net.Dialer{Timeout: metadataProbeTimeout, Resolver: &net.Resolver{PreferGo: true}}
	client := &http.Client{
		Timeout: metadataProbeTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   metadataProbeTimeout,
			ResponseHeaderTimeout: metadataProbeTimeout,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}
