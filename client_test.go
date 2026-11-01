package trustclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildRequiresURLTokenAndAccount(t *testing.T) {
	old := metadataProbeTimeout
	metadataProbeTimeout = time.Millisecond
	resetMetadataCache()
	t.Setenv(GitHubActionsRequestURLEnv, "")
	t.Setenv(GitHubActionsRequestTokenEnv, "")
	t.Setenv(GCPMetadataHostEnv, "")
	t.Setenv(GCPCloudRunServiceEnv, "")
	t.Setenv(AzureIdentityEndpointEnv, "")
	t.Setenv(AzureIdentityHeaderEnv, "")
	t.Setenv(AzureDevOpsRequestURIEnv, "")
	t.Setenv(AzureDevOpsAccessTokenEnv, "")
	t.Cleanup(func() {
		metadataProbeTimeout = old
		resetMetadataCache()
	})

	_, err := NewBuilder().AccountID("acct-1").APIToken("key").Build(context.Background())
	if err == nil || err.Error() != "url is required" {
		t.Fatalf("missing url: %v", err)
	}

	_, err = NewBuilder().URL("https://trust.example.com").AccountID("acct-1").Build(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "apiToken is required") {
		t.Fatalf("missing token: %v", err)
	}

	_, err = NewBuilder().URL("https://trust.example.com").APIToken("key").Build(context.Background())
	if err == nil || err.Error() != "accountId is required" {
		t.Fatalf("missing account: %v", err)
	}
}

func TestBuildRejectsBlankTokenAndBadURL(t *testing.T) {
	_, err := NewBuilder().APIToken("  ").URL("https://trust.example.com").AccountID("acct-1").Build(context.Background())
	if err == nil || err.Error() != "apiToken must not be blank" {
		t.Fatalf("blank token: %v", err)
	}
	_, err = NewBuilder().AccountID("  ").URL("https://trust.example.com").APIToken("key").Build(context.Background())
	if err == nil || err.Error() != "accountId must not be blank" {
		t.Fatalf("blank account: %v", err)
	}
	_, err = NewBuilder().URL("ftp://files.example.com").APIToken("key").AccountID("acct-1").Build(context.Background())
	if err == nil || err.Error() != "url must use http or https" {
		t.Fatalf("ftp: %v", err)
	}
	_, err = NewBuilder().URL("/relative").APIToken("key").AccountID("acct-1").Build(context.Background())
	if err == nil || err.Error() != "url must be an absolute http or https URI" {
		t.Fatalf("relative: %v", err)
	}
	_, err = NewBuilder().URL("https://").APIToken("key").AccountID("acct-1").Build(context.Background())
	if err == nil || err.Error() != "url must be an absolute http or https URI" {
		t.Fatalf("empty host: %v", err)
	}
}

func TestBuildTrimsURLAndKeepsToken(t *testing.T) {
	client, err := NewBuilder().
		URL("  https://trust.example.com/api  ").
		AccountID("acct-1").
		APIToken("secret-key").
		ConnectTimeout(5 * time.Second).
		FollowRedirects(RedirectNormal).
		Version(HTTP1).
		NoProxy().
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.URL() != "https://trust.example.com/api" {
		t.Fatalf("url %q", client.URL())
	}
	if client.APIToken() != "secret-key" || client.AccountID() != "acct-1" {
		t.Fatalf("identity %s %s", client.APIToken(), client.AccountID())
	}
	if client.HTTPClient() == nil {
		t.Fatal("missing http client")
	}
}

func TestCustomHTTPClientIsNotClosed(t *testing.T) {
	custom := &http.Client{Timeout: 3 * time.Second}
	client, err := NewBuilder().
		URL("http://localhost:8080").
		AccountID("acct-1").
		APIToken("key").
		HTTPClient(custom).
		Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if client.HTTPClient() != custom {
		t.Fatal("custom client was replaced")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAssetCallsAndStepUp(t *testing.T) {
	var hits int
	var sawCode string
	var prompted string
	const serverPrompt = "Please enter verification code emailed to you"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("x-api-token") != "test-token" {
			t.Errorf("token header %q", r.Header.Get("x-api-token"))
		}
		switch r.URL.Path {
		case "/gateway/rest/api/v1/secret/acct-test/fetch":
			if r.Header.Get("Accept") != "text/plain" {
				t.Errorf("accept %q", r.Header.Get("Accept"))
			}
			code := r.Header.Get(AccessCodeHeader)
			sawCode = code
			if hits == 1 {
				w.Header().Set(AccessResponseHeader, "EMAIL")
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(AccessRequiredStatus)
				_, _ = io.WriteString(w, serverPrompt)
				return
			}
			if code != "email-code-99" {
				http.Error(w, "Invalid email verification code", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, "super-secret-value")
		case "/gateway/rest/api/v1/secret/acct-test/get/mvusgvkv5":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"mvusgvkv5","account_id":"acct-test","name":"app","status":"ACTIVE","secret_type":"CONFIGURATION","version":3,"date_created":"2026-05-01T12:00:00.000Z"}`)
		case "/gateway/rest/api/v1/secret/acct-test/fetch/mvusgvkv5":
			_, _ = io.WriteString(w, "mode=prod\n")
		case "/gateway/rest/api/v1/secret/acct-test/fetch/b5fqj6c8d":
			_, _ = io.WriteString(w, `{"username":"ubuntu","key":"pem-body","key_algorithm":"ED25519","key_size":"256"}`)
		case "/gateway/rest/api/v1/secret/acct-test/fetch/v5q7pspif":
			_, _ = io.WriteString(w, "hunter2")
		case "/gateway/rest/api/v1/secret/acct-test/fetch/17bu1p62uq":
			_, _ = io.WriteString(w, `{"username":"alice","password":"s3cret"}`)
		case "/gateway/rest/api/v1/secret/acct-test/fetch/k8m7c8pps":
			_, _ = io.WriteString(w, `{"key":"pk","key_algorithm":"RSA","key_size":"2048"}`)
		case "/gateway/rest/api/v1/cert/acct-test/get/cert-1":
			_, _ = io.WriteString(w, `{"id":"cert-1","primary_domain":"example.com","cert_validation":"DV","san_domains":"www.example.com"}`)
		case "/gateway/rest/api/v1/cert/acct-test/fetch/cert-1":
			_, _ = io.WriteString(w, "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n")
		case "/gateway/rest/api/v1/cert/acct-test/fetch-bundle/cert-1":
			_, _ = io.WriteString(w, "BUNDLE")
		case "/gateway/rest/api/v1/token/acct-test/get/tok-1":
			_, _ = io.WriteString(w, `{"id":"tok-1","token_type":"SECRET","protocols":["SSH","HTTPS"],"secret_id":"mvusgvkv5"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc, err := NewBuilder().
		URL(srv.URL + "/gateway").
		AccountID("acct-test").
		APIToken("test-token").
		AuthCodePrompt(func(reason string) (string, error) {
			prompted = reason
			return "email-code-99", nil
		}).
		BuildService(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx := context.Background()
	contents, err := svc.FetchSecret(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if contents != "super-secret-value" || prompted != serverPrompt || sawCode != "email-code-99" {
		t.Fatalf("step-up contents=%q prompted=%q code=%q hits=%d", contents, prompted, sawCode, hits)
	}

	secret, err := svc.GetSecret(ctx, "mvusgvkv5")
	if err != nil {
		t.Fatal(err)
	}
	if secret.ID != "mvusgvkv5" || secret.SecretType != SecretTypeConfiguration || !secret.Status.IsActive() || secret.Version != 3 {
		t.Fatalf("secret %+v", secret)
	}
	if secret.DateCreated == nil || secret.DateCreated.UTC().Format(time.RFC3339) != "2026-05-01T12:00:00Z" {
		t.Fatalf("created %#v", secret.DateCreated)
	}
	if secret.Status.CanSuspend() != true || secret.Status.CanRevoke() != true {
		t.Fatal("status helpers")
	}

	cfg, err := svc.GetSecretAsConfiguration(ctx, "mvusgvkv5")
	if err != nil || cfg.Secret != "mode=prod\n" {
		t.Fatalf("config %q %v", cfg.Secret, err)
	}
	pemSecret, err := svc.GetSecretAsPEM(ctx, "b5fqj6c8d")
	if err != nil || pemSecret.Username != "ubuntu" || !pemSecret.PQReady() {
		t.Fatalf("pem %+v %v", pemSecret, err)
	}
	pw, err := svc.GetSecretAsPassword(ctx, "v5q7pspif")
	if err != nil || pw.Password != "hunter2" {
		t.Fatalf("password %+v %v", pw, err)
	}
	cred, err := svc.GetSecretAsCredentials(ctx, "17bu1p62uq")
	if err != nil || cred.Username != "alice" || cred.Password != "s3cret" {
		t.Fatalf("cred %+v %v", cred, err)
	}
	pk, err := svc.GetSecretAsPrivateKey(ctx, "k8m7c8pps")
	if err != nil || pk.Key != "pk" || pk.PQReady() {
		t.Fatalf("pk %+v %v", pk, err)
	}

	cert, err := svc.GetCertificate(ctx, "cert-1")
	if err != nil || cert.PrimaryDomain != "example.com" || cert.CertValidation.Description() != "Domain Validated" {
		t.Fatalf("cert %+v %v", cert, err)
	}
	if len(cert.SANDomains) != 1 || cert.SANDomains[0] != "www.example.com" {
		t.Fatalf("sans %#v", cert.SANDomains)
	}
	leaf, err := svc.FetchCertificate(ctx, "cert-1")
	if err != nil || !strings.Contains(leaf, "BEGIN CERTIFICATE") {
		t.Fatalf("leaf %q %v", leaf, err)
	}
	bundle, err := svc.FetchCertificateBundle(ctx, "cert-1")
	if err != nil || bundle != "BUNDLE" {
		t.Fatalf("bundle %q %v", bundle, err)
	}
	tok, err := svc.GetToken(ctx, "tok-1")
	if err != nil || tok.TokenType != TokenTypeSecret || len(tok.Protocols) != 2 || !tok.Protocols[0].IsSSHFamily() {
		t.Fatalf("token %+v %v", tok, err)
	}
}

func TestHTTPErrorBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/v1/secret/acct/get/missing":
			w.Header().Set("x-body-type", "certlocker.gateway.api.model.ErrorDTO")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error_message":"secret not found"}`)
		case "/rest/api/v1/secret/acct/get/denied":
			w.Header().Set("x-body-type", "certlocker.core.exceptions.CLErrorException")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"message":"denied by policy"}}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "boom")
		}
	}))
	defer srv.Close()

	client, err := NewBuilder().URL(srv.URL).AccountID("acct").APIToken("tok").Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.GetSecret(context.Background(), "missing")
	var te *Error
	if !errors.As(err, &te) || !te.HasTrustError() || te.HTTPStatus != 404 || te.Message != "secret not found" {
		t.Fatalf("dto error %#v", err)
	}
	_, err = client.GetSecret(context.Background(), "denied")
	te = nil
	if !errors.As(err, &te) || te.HTTPStatus != 403 || te.Message != "denied by policy" {
		t.Fatalf("cl error %#v", err)
	}
	_, err = client.GetSecret(context.Background(), "other")
	te = nil
	if !errors.As(err, &te) || te.HTTPStatus != 500 || te.Message != "boom" {
		t.Fatalf("plain %#v", err)
	}
}

func TestStepUpWithoutPrompt(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "access code required")
	}))
	defer srv.Close()
	client, err := NewBuilder().URL(srv.URL).AccountID("acct").APIToken("tok").Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.FetchSecret(context.Background(), "s1")
	var te *Error
	if !errors.As(err, &te) || te.HTTPStatus != 401 || te.Message != "access code required" || hits != 1 {
		t.Fatalf("err=%v hits=%d", err, hits)
	}
	if err := client.PromptForAccessCode("x"); err == nil || !strings.Contains(err.Error(), "No AuthCodePrompt") {
		t.Fatalf("prompt %v", err)
	}
}

func TestRedirectNeverIsDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/final") {
			_, _ = io.WriteString(w, "ok")
			return
		}
		http.Redirect(w, r, "/rest/api/v1/secret/acct/fetch/s/final", http.StatusFound)
	}))
	defer srv.Close()
	client, err := NewBuilder().URL(srv.URL).AccountID("acct").APIToken("tok").Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.FetchSecret(context.Background(), "s")
	var te *Error
	if !errors.As(err, &te) || te.HTTPStatus != http.StatusFound {
		t.Fatalf("redirect followed or unexpected: %v", err)
	}

	following, err := NewBuilder().URL(srv.URL).AccountID("acct").APIToken("tok").FollowRedirects(RedirectAlways).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer following.Close()
	body, err := following.FetchSecret(context.Background(), "s")
	if err != nil || body != "ok" {
		t.Fatalf("follow %q %v", body, err)
	}
}

func TestConsoleAuthCodePrompt(t *testing.T) {
	code, err := readAuthCode(strings.NewReader("  123456\n"), io.Discard, "code")
	if err != nil || code != "123456" {
		t.Fatalf("code %q %v", code, err)
	}
	_, err = readAuthCode(strings.NewReader("\n"), io.Discard, "")
	if err == nil {
		t.Fatal("expected empty code error")
	}
}

func TestAssetHelpers(t *testing.T) {
	if AssetStatusSuspended.CanResume() != true || AssetStatusRevoked.CanRevoke() {
		t.Fatal("status")
	}
	if !SecretTypePEM.HasAlgo() || SecretTypePassword.HasAlgo() {
		t.Fatal("algo")
	}
	if CertificateValidationEV.Description() != "Extended Validation" {
		t.Fatal("ev")
	}
	if ProtocolSFTP.IsSSHFamily() != true || ProtocolHTTPS.IsSSHFamily() {
		t.Fatal("protocol")
	}
}
