package trustclient

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const dogfoodPrivatePEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF9AaYYFhQwyap4byHSJdP10An9RnSyjIs7938lU7Sm/
-----END PRIVATE KEY-----
`

const dogfoodPublicPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWSHYSlK7bRVNfnJZkuuPdvt8YVdUc4YQlsLB1DfEV3U=
-----END PUBLIC KEY-----
`

func TestMintDeviceJWTMatchesClaimShape(t *testing.T) {
	aud, err := AudienceForAccount("acct-dogfood")
	if err != nil || aud != "https://trust.certlocker.io/oidc/acct-dogfood" {
		t.Fatal(aud, err)
	}
	jwt, err := MintDeviceJWT(DeviceOIDCConfig{
		Audience:      aud,
		DeviceID:      "laptop-dogfood-1",
		PrivateKeyPEM: dogfoodPrivatePEM,
		KeyID:         "trust-device-dexta",
		TTL:           5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyDeviceJWT(t, jwt, dogfoodPublicPEM, aud, "laptop-dogfood-1", "trust-device-dexta")
}

func TestDeviceKeyFileAndRejectOpenSSH(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device.pem"
	if err := os.WriteFile(path, []byte(dogfoodPrivatePEM), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadDevicePrivateKey(path)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal(err)
	}
	_, err = ParseDevicePrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n-----END OPENSSH PRIVATE KEY-----")
	if err == nil || !strings.Contains(err.Error(), "PKCS#8") {
		t.Fatalf("openssh: %v", err)
	}
	_, err = MintDeviceJWT(DeviceOIDCConfig{Audience: "https://trust.certlocker.io/oidc/a", DeviceID: "d1"})
	if err == nil || !strings.Contains(err.Error(), "privateKeyPath") {
		t.Fatalf("config: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	generated := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	reloaded, err := ParseDevicePrivateKey(string(generated))
	if err != nil {
		t.Fatal(err)
	}
	token, err := MintDeviceJWT(DeviceOIDCConfig{
		Audience:      "https://trust.certlocker.io/oidc/acct",
		DeviceID:      "machine-1",
		PrivateKeyPEM: string(generated),
		KeyID:         "kid-1",
		TTL:           time.Minute,
	})
	if err != nil || !strings.HasPrefix(token, "eyJ") {
		t.Fatal(token, err)
	}
	if !reloaded.Equal(priv) {
		t.Fatal("reloaded key differs")
	}
	verifyDeviceJWT(t, token, publicPEM(pub), "https://trust.certlocker.io/oidc/acct", "machine-1", "kid-1")
	_ = path
}

func TestExchangeAndProviders(t *testing.T) {
	var gotBody map[string]string
	trust := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/v1/oidc/exchange" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = io.WriteString(w, `{"token_id":"minted-1","expires_at":"2026-11-01T12:00:00.000Z","token_type":"SECRET","account_id":"acct-9","principal_id":"prin-1"}`)
	}))
	defer trust.Close()

	gha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gha-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "audience=") {
			http.Error(w, "missing audience", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"value":"gha.jwt.sig"}`)
	}))
	defer gha.Close()

	t.Setenv(GitHubActionsRequestURLEnv, gha.URL)
	t.Setenv(GitHubActionsRequestTokenEnv, "gha-token")
	if !GitHubActionsAvailable() {
		t.Fatal("expected github actions to be available")
	}

	result, err := ExchangeGitHubActions(context.Background(), trust.URL, "https://trust.certlocker.io/oidc/acct-9", TokenTypeSecret)
	if err != nil {
		t.Fatal(err)
	}
	if result.TokenID != "minted-1" || result.AccountID != "acct-9" || result.PrincipalID != "prin-1" || result.TokenType != "SECRET" {
		t.Fatalf("%+v", result)
	}
	if result.ExpiresAt == nil || result.ExpiresAt.IsZero() {
		t.Fatal("missing expiry")
	}
	if gotBody["id_token"] != "gha.jwt.sig" || gotBody["idToken"] != "gha.jwt.sig" || gotBody["token_type"] != "SECRET" {
		t.Fatalf("body %#v", gotBody)
	}

	client, err := FromIDToken(context.Background(), trust.URL, "raw.jwt.sig")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.APIToken() != "minted-1" || client.AccountID() != "acct-9" {
		t.Fatalf("client %s %s", client.APIToken(), client.AccountID())
	}

	_, err = ExchangeIDToken(context.Background(), trust.URL, "x", TokenTypeHost)
	if err == nil || !strings.Contains(err.Error(), "SECRET, CERTIFICATE, or MCP") {
		t.Fatalf("mint type %v", err)
	}
}

func TestCamelExchangeAndDeviceFile(t *testing.T) {
	trust := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"tokenId":"camel-token","accountId":"acct-camel","tokenType":"MCP"}`)
	}))
	defer trust.Close()

	dir := t.TempDir()
	path := dir + "/device.pem"
	if err := os.WriteFile(path, []byte(dogfoodPrivatePEM), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := FromDeviceOIDCFile(context.Background(), trust.URL, "https://trust.certlocker.io/oidc/acct-camel", "laptop-1", path, "kid")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.APIToken() != "camel-token" || client.AccountID() != "acct-camel" {
		t.Fatalf("%s %s", client.APIToken(), client.AccountID())
	}

	result, err := ExchangeDeviceOIDC(context.Background(), trust.URL, DeviceOIDCConfig{
		Audience:      "https://trust.certlocker.io/oidc/acct-camel",
		DeviceID:      "laptop-1",
		PrivateKeyPEM: dogfoodPrivatePEM,
	}, TokenTypeMCP)
	if err != nil || result.TokenType != "MCP" {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestAmbientBuildAndBreakGlass(t *testing.T) {
	gha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":"ambient.jwt"}`)
	}))
	defer gha.Close()
	trust := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"token_id":"from-ambient","account_id":"acct-amb"}`)
	}))
	defer trust.Close()

	t.Setenv(GitHubActionsRequestURLEnv, gha.URL)
	t.Setenv(GitHubActionsRequestTokenEnv, "t")
	client, err := FromAmbientOIDC(context.Background(), trust.URL, "https://trust.certlocker.io/oidc/acct-amb")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.APIToken() != "from-ambient" || client.AccountID() != "acct-amb" {
		t.Fatalf("%s %s", client.APIToken(), client.AccountID())
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer bad.Close()
	t.Setenv(GitHubActionsRequestURLEnv, bad.URL)
	glass, err := NewBuilder().
		URL(trust.URL).
		AccountID("acct-keep").
		APIToken("break-glass").
		OIDCAudience("https://trust.certlocker.io/oidc/acct-keep").
		PreferAmbientOIDC(true).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer glass.Close()
	if glass.APIToken() != "break-glass" || glass.AccountID() != "acct-keep" {
		t.Fatalf("break glass %s %s", glass.APIToken(), glass.AccountID())
	}
}

func TestGCPAndAzureAndADORequests(t *testing.T) {
	gcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "flavor", http.StatusBadRequest)
			return
		}
		if !strings.Contains(r.URL.Path, "/computeMetadata/v1/instance/service-accounts/default/identity") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, " gcp.jwt \n")
	}))
	defer gcp.Close()
	t.Setenv(GCPMetadataHostEnv, strings.TrimPrefix(gcp.URL, "http://"))
	if !GCPAvailable() {
		t.Fatal("gcp should be available from env")
	}
	jwt, err := RequestGCPIDToken(context.Background(), "https://trust.certlocker.io/oidc/a")
	if err != nil || jwt != "gcp.jwt" {
		t.Fatalf("%q %v", jwt, err)
	}

	azure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-IDENTITY-HEADER") != "secret-header" {
			http.Error(w, "header", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "client_id=client-1") {
			http.Error(w, "client", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"azure.jwt"}`)
	}))
	defer azure.Close()
	t.Setenv(AzureIdentityEndpointEnv, azure.URL)
	t.Setenv(AzureIdentityHeaderEnv, "secret-header")
	t.Setenv(AzureClientIDEnv, "client-1")
	azureJWT, err := RequestAzureIDToken(context.Background(), "https://trust.certlocker.io/oidc/a")
	if err != nil || azureJWT != "azure.jwt" {
		t.Fatalf("%q %v", azureJWT, err)
	}

	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "api-version=7.1") || !strings.Contains(r.URL.RawQuery, "serviceConnectionId=sc-1") {
			http.Error(w, r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"oidcToken":"ado.jwt"}`)
	}))
	defer ado.Close()
	t.Setenv(AzureDevOpsRequestURIEnv, ado.URL+"/oidc")
	t.Setenv(AzureDevOpsAccessTokenEnv, "ado-access")
	t.Setenv(AzureDevOpsServiceConnectionEnv, "sc-1")
	if !AzureDevOpsAvailable() {
		t.Fatal("ado")
	}
	adoJWT, err := RequestAzureDevOpsIDToken(context.Background())
	if err != nil || adoJWT != "ado.jwt" {
		t.Fatalf("%q %v", adoJWT, err)
	}
}

func TestExchangeDeniedAndMissingToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"error_message":"principal not allowed"}`)
	}))
	defer srv.Close()
	_, err := ExchangeIDToken(context.Background(), srv.URL, "jwt", "")
	if err == nil || !strings.Contains(err.Error(), "principal not allowed") {
		t.Fatal(err)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"account_id":"a"}`)
	}))
	defer empty.Close()
	_, err = ExchangeIDToken(context.Background(), empty.URL, "jwt", "")
	if err == nil || !strings.Contains(err.Error(), "missing tokenId") {
		t.Fatal(err)
	}
}

func TestGitHubUnavailable(t *testing.T) {
	t.Setenv(GitHubActionsRequestURLEnv, "")
	t.Setenv(GitHubActionsRequestTokenEnv, "")
	if GitHubActionsAvailable() {
		t.Fatal("github should be unavailable")
	}
}

func verifyDeviceJWT(t *testing.T, jwt, publicPEM, audience, deviceID, kid string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("parts %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "EdDSA" || header.Kid != kid {
		t.Fatalf("header %+v", header)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims deviceClaims
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != DeviceIssuer || claims.Audience != audience || claims.Subject != "device:"+deviceID || claims.DeviceID != deviceID {
		t.Fatalf("claims %+v", claims)
	}
	if claims.Expiry <= claims.IssuedAt {
		t.Fatalf("exp %d iat %d", claims.Expiry, claims.IssuedAt)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		t.Fatal("public pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature")
	}
}

func publicPEM(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
