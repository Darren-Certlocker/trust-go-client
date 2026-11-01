package trustclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Builder builds a [Client] for a Trust URL and an API token.
//
// When no HTTP client is supplied, the connect timeout is [DefaultConnectTimeout]
// and redirects are not followed. [Builder.HTTPClient] uses that client as given;
// connect timeout, proxy, TLS, and redirect settings then apply only when no
// custom client is set.
type Builder struct {
	rawURL    string
	urlErr    error
	apiToken  string
	apiTokErr error
	accountID string
	acctErr   error
	audience  string
	audErr    error

	preferAmbient bool
	prompt        AuthCodePrompt

	connectTimeout time.Duration
	connectErr     error
	requestTimeout time.Duration
	requestErr     error
	redirects      RedirectPolicy
	version        HTTPVersion
	proxy          *url.URL
	proxyErr       error
	noProxy        bool
	tlsConfig      *tls.Config
	jar            http.CookieJar
	localAddr      net.Addr
	httpClient     *http.Client
	httpErr        error
}

// NewBuilder returns a builder with the default connect timeout.
func NewBuilder() *Builder {
	return &Builder{}
}

// URL sets the Trust base URL. Surrounding whitespace is ignored.
// The URL must be absolute http or https.
func (b *Builder) URL(raw string) *Builder {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		b.rawURL = ""
		b.urlErr = errors.New("url must be an absolute http or https URI")
		return b
	}
	if err := validateBaseURL(trimmed); err != nil {
		b.rawURL = ""
		b.urlErr = err
		return b
	}
	b.urlErr = nil
	b.rawURL = trimmed
	return b
}

// APIToken sets the API token sent as the x-api-token header.
func (b *Builder) APIToken(apiToken string) *Builder {
	if strings.TrimSpace(apiToken) == "" {
		b.apiToken = ""
		b.apiTokErr = errors.New("apiToken must not be blank")
		return b
	}
	b.apiTokErr = nil
	b.apiToken = apiToken
	return b
}

// AccountID sets the tenant account id for Gateway paths.
// It must match the API token's account.
func (b *Builder) AccountID(accountID string) *Builder {
	if strings.TrimSpace(accountID) == "" {
		b.accountID = ""
		b.acctErr = errors.New("accountId must not be blank")
		return b
	}
	b.acctErr = nil
	b.accountID = accountID
	return b
}

// OIDCAudience sets the per-account OIDC audience, for example
// https://trust.certlocker.io/oidc/<accountId>.
func (b *Builder) OIDCAudience(audience string) *Builder {
	if strings.TrimSpace(audience) == "" {
		b.audience = ""
		b.audErr = errors.New("oidcAudience must not be blank")
		return b
	}
	b.audErr = nil
	b.audience = audience
	return b
}

// PreferAmbientOIDC exchanges ambient GitHub Actions, GCP, Azure, or Azure
// DevOps OIDC during Build before using a break-glass API token.
func (b *Builder) PreferAmbientOIDC(prefer bool) *Builder {
	b.preferAmbient = prefer
	return b
}

// AuthCodePrompt sets the prompt used when the Gateway requires 2FA / access code.
func (b *Builder) AuthCodePrompt(prompt AuthCodePrompt) *Builder {
	b.prompt = prompt
	return b
}

// ConnectTimeout sets the TCP connect timeout. Zero or negative is rejected.
// When unset, the timeout is [DefaultConnectTimeout].
func (b *Builder) ConnectTimeout(d time.Duration) *Builder {
	if d <= 0 {
		b.connectErr = errors.New("connectTimeout must be greater than 0")
		return b
	}
	b.connectErr = nil
	b.connectTimeout = d
	return b
}

// RequestTimeout sets the overall HTTP client timeout for asset calls.
// Zero means no overall timeout; cancel the context to stop a call.
func (b *Builder) RequestTimeout(d time.Duration) *Builder {
	if d < 0 {
		b.requestErr = errors.New("requestTimeout must be >= 0")
		return b
	}
	b.requestErr = nil
	b.requestTimeout = d
	return b
}

// FollowRedirects sets the redirect policy. The default is [RedirectNever].
func (b *Builder) FollowRedirects(policy RedirectPolicy) *Builder {
	b.redirects = policy
	return b
}

// Version sets the preferred HTTP version.
func (b *Builder) Version(version HTTPVersion) *Builder {
	b.version = version
	return b
}

// Proxy sets an explicit proxy URL.
func (b *Builder) Proxy(proxyURL string) *Builder {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		b.proxy = nil
		b.proxyErr = errors.New("proxy must be an absolute URL")
		return b
	}
	b.proxyErr = nil
	b.proxy = parsed
	b.noProxy = false
	return b
}

// NoProxy disables proxy use.
func (b *Builder) NoProxy() *Builder {
	b.noProxy = true
	b.proxy = nil
	b.proxyErr = nil
	return b
}

// TLSConfig sets the TLS configuration for the HTTP client.
func (b *Builder) TLSConfig(cfg *tls.Config) *Builder {
	b.tlsConfig = cfg
	return b
}

// CookieJar sets the cookie jar for the HTTP client.
func (b *Builder) CookieJar(jar http.CookieJar) *Builder {
	b.jar = jar
	return b
}

// LocalAddr sets the local address the HTTP client binds to.
// Nil means any local address.
func (b *Builder) LocalAddr(addr net.Addr) *Builder {
	b.localAddr = addr
	return b
}

// HTTPClient uses this HTTP client for asset calls, in place of the transport
// settings on the builder. The caller keeps ownership; [Client.Close] does not
// close it.
func (b *Builder) HTTPClient(client *http.Client) *Builder {
	if client == nil {
		b.httpClient = nil
		b.httpErr = errors.New("http client is required")
		return b
	}
	b.httpErr = nil
	b.httpClient = client
	return b
}

// Build builds the client. ctx is used for ambient OIDC exchange when that
// path runs. Pass a non-nil context.
func (b *Builder) Build(ctx context.Context) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if b.urlErr != nil {
		return nil, b.urlErr
	}
	if b.apiTokErr != nil {
		return nil, b.apiTokErr
	}
	if b.acctErr != nil {
		return nil, b.acctErr
	}
	if b.audErr != nil {
		return nil, b.audErr
	}
	if b.httpErr != nil {
		return nil, b.httpErr
	}
	if strings.TrimSpace(b.rawURL) == "" {
		return nil, errors.New("url is required")
	}

	httpClient := b.httpClient
	ownsHTTP := false
	if httpClient == nil {
		if b.connectErr != nil {
			return nil, b.connectErr
		}
		if b.requestErr != nil {
			return nil, b.requestErr
		}
		if b.proxyErr != nil {
			return nil, b.proxyErr
		}
		var err error
		httpClient, err = buildHTTPClient(transportConfig{
			connectTimeout: b.connectTimeout,
			requestTimeout: b.requestTimeout,
			redirects:      b.redirects,
			version:        b.version,
			proxy:          b.proxy,
			noProxy:        b.noProxy,
			tlsConfig:      b.tlsConfig,
			jar:            b.jar,
			localAddr:      b.localAddr,
		})
		if err != nil {
			return nil, err
		}
		ownsHTTP = true
	}

	apiToken := b.apiToken
	accountID := b.accountID
	if strings.TrimSpace(apiToken) == "" || b.preferAmbient {
		exchanged, usedAmbient, err := b.exchangeAmbient(ctx)
		if err != nil {
			if strings.TrimSpace(apiToken) == "" {
				if ownsHTTP {
					httpClient.CloseIdleConnections()
				}
				return nil, fmt.Errorf("ambient OIDC exchange failed and no apiToken set: %w", err)
			}
		} else if usedAmbient {
			apiToken = exchanged.TokenID
			if strings.TrimSpace(accountID) == "" {
				accountID = exchanged.AccountID
			}
		}
	}
	if strings.TrimSpace(apiToken) == "" {
		if ownsHTTP {
			httpClient.CloseIdleConnections()
		}
		return nil, errors.New("apiToken is required (or enable ambient OIDC with oidcAudience / preferAmbientOidc)")
	}
	if strings.TrimSpace(accountID) == "" {
		if ownsHTTP {
			httpClient.CloseIdleConnections()
		}
		return nil, errors.New("accountId is required")
	}
	return &Client{
		baseURL:   b.rawURL,
		apiToken:  apiToken,
		accountID: accountID,
		http:      httpClient,
		ownsHTTP:  ownsHTTP,
		prompt:    b.prompt,
	}, nil
}

// BuildService builds a client and wraps it in a [Service].
func (b *Builder) BuildService(ctx context.Context) (*Service, error) {
	client, err := b.Build(ctx)
	if err != nil {
		return nil, err
	}
	return NewService(client), nil
}

func (b *Builder) exchangeAmbient(ctx context.Context) (ExchangeResult, bool, error) {
	gha := GitHubActionsAvailable()
	gcp := !gha && GCPAvailable()
	azure := !gha && !gcp && AzureAvailable()
	ado := !gha && !gcp && !azure && AzureDevOpsAvailable()
	if !b.preferAmbient && !gha && !gcp && !azure && !ado {
		return ExchangeResult{}, false, nil
	}
	result, err := exchangeAmbient(ctx, b.rawURL, b.audience, gha, gcp, azure, ado)
	if err != nil {
		return ExchangeResult{}, false, err
	}
	return result, true, nil
}

func exchangeAmbient(ctx context.Context, trustURL, audience string, gha, gcp, azure, ado bool) (ExchangeResult, error) {
	switch {
	case gha:
		if err := requireAudience(audience, "GitHub Actions"); err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeGitHubActions(ctx, trustURL, audience, "")
	case gcp:
		if err := requireAudience(audience, "GCP"); err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeGCP(ctx, trustURL, audience, "")
	case azure:
		if err := requireAudience(audience, "Azure"); err != nil {
			return ExchangeResult{}, err
		}
		return ExchangeAzure(ctx, trustURL, audience, "")
	case ado:
		return ExchangeAzureDevOps(ctx, trustURL, "")
	default:
		return ExchangeResult{}, trustErr("No ambient OIDC provider available (GitHub Actions, GCP, Azure, or Azure DevOps)")
	}
}

func requireAudience(audience, provider string) error {
	if strings.TrimSpace(audience) == "" {
		return trustErr("oidcAudience is required for " + provider + " OIDC")
	}
	return nil
}

// FromAmbientOIDC builds a client by exchanging the first available ambient
// OIDC provider. accountId is taken from the exchange response.
func FromAmbientOIDC(ctx context.Context, trustURL, audience string) (*Client, error) {
	return NewBuilder().URL(trustURL).OIDCAudience(audience).PreferAmbientOIDC(true).Build(ctx)
}

// FromIDToken exchanges a signed OIDC JWT and builds a client.
// The exchange response must include accountId.
func FromIDToken(ctx context.Context, trustURL, idToken string) (*Client, error) {
	if strings.TrimSpace(trustURL) == "" {
		return nil, errors.New("trustUrl must not be blank")
	}
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("idToken must not be blank")
	}
	if err := validateBaseURL(strings.TrimSpace(trustURL)); err != nil {
		return nil, err
	}
	exchanged, err := ExchangeIDToken(ctx, strings.TrimSpace(trustURL), idToken, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(exchanged.AccountID) == "" {
		return nil, trustErr("OIDC exchange response missing accountId")
	}
	return NewBuilder().
		URL(strings.TrimSpace(trustURL)).
		APIToken(exchanged.TokenID).
		AccountID(exchanged.AccountID).
		Build(ctx)
}

// FromDeviceOIDC mints an Ed25519 device JWT, exchanges it, and builds a client.
// The principal default mint type is used.
func FromDeviceOIDC(ctx context.Context, trustURL string, cfg DeviceOIDCConfig) (*Client, error) {
	if strings.TrimSpace(trustURL) == "" {
		return nil, errors.New("trustUrl must not be blank")
	}
	jwt, err := MintDeviceJWT(cfg)
	if err != nil {
		return nil, err
	}
	return FromIDToken(ctx, trustURL, jwt)
}

// FromDeviceOIDCFile is FromDeviceOIDC with the private key read from path.
// keyID may be empty when the enrolled principal has no key id.
func FromDeviceOIDCFile(ctx context.Context, trustURL, audience, deviceID, privateKeyPath, keyID string) (*Client, error) {
	return FromDeviceOIDC(ctx, trustURL, DeviceOIDCConfig{
		Audience:       audience,
		DeviceID:       deviceID,
		PrivateKeyPath: privateKeyPath,
		KeyID:          keyID,
	})
}

func validateBaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("url must be an absolute http or https URI")
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http") {
		return errors.New("url must use http or https")
	}
	return nil
}
