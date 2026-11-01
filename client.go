package trustclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// AccessCodeHeader is the step-up 2FA / access code sent on user-bound tokens.
	AccessCodeHeader = "x-access-code"
	// AccessResponseHeader names the Gateway challenge type (ACCESS_CODE, OTP, or EMAIL).
	AccessResponseHeader = "x-access-response"
	// AccessRequiredStatus is the HTTP status the Gateway uses for step-up.
	// The response body is the prompt text to show.
	AccessRequiredStatus = http.StatusUnauthorized

	// DefaultConnectTimeout is the connect timeout used when the caller does not set one.
	DefaultConnectTimeout = 10 * time.Second

	apiPrefix       = "/rest/api/v1"
	mediaJSON       = "application/json"
	mediaText       = "text/plain"
	headerAPIToken  = "x-api-token"
	headerBodyType  = "x-body-type"
	bodyTypeError   = "certlocker.gateway.api.model.ErrorDTO"
	bodyTypeCLError = "certlocker.core.exceptions.CLErrorException"
)

// Client calls a Certlocker Trust Gateway.
//
// Get methods return the asset record as JSON. Fetch methods return the asset
// contents. Create one with [NewBuilder], [FromAmbientOIDC], [FromIDToken], or
// [FromDeviceOIDC].
//
// Multi-tenant paths are /rest/api/v1/{resource}/{accountId}/….
// An empty id omits the final path segment. Secret fetch supports that form
// for a token assigned to one secret. Certificate and token routes require an id.
type Client struct {
	baseURL   string
	apiToken  string
	accountID string
	http      *http.Client
	ownsHTTP  bool
	prompt    AuthCodePrompt

	mu         sync.Mutex
	accessCode string
	closeOnce  sync.Once
}

// URL returns the Trust base URL.
func (c *Client) URL() string { return c.baseURL }

// APIToken returns the API token sent as the x-api-token header.
func (c *Client) APIToken() string { return c.apiToken }

// AccountID returns the account id used in Gateway paths.
func (c *Client) AccountID() string { return c.accountID }

// HTTPClient returns the HTTP client used for asset requests.
func (c *Client) HTTPClient() *http.Client { return c.http }

// SetAccessCode sets a 2FA / access code for subsequent requests.
func (c *Client) SetAccessCode(accessCode string) {
	c.mu.Lock()
	c.accessCode = accessCode
	c.mu.Unlock()
}

// PromptForAccessCode asks the configured prompt for a 2FA / access code.
func (c *Client) PromptForAccessCode(reason string) error {
	if c.prompt == nil {
		return trustErr("No AuthCodePrompt configured; call Builder.AuthCodePrompt(...)")
	}
	code, err := c.prompt(reason)
	if err != nil {
		return wrapErr("Failed to read authentication code: "+err.Error(), err)
	}
	c.SetAccessCode(code)
	return nil
}

// Close releases idle connections on the HTTP client this client created.
// A caller-supplied HTTP client is left open.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.ownsHTTP && c.http != nil {
			c.http.CloseIdleConnections()
		}
	})
	return nil
}

// GetSecret returns the secret record for id as JSON.
// An empty id requests /secret/{accountId}/get with no asset segment.
func (c *Client) GetSecret(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "secret", "get", id, mediaJSON, true)
}

// FetchSecret returns the contents of the secret.
// An empty id requests the secret assigned to this token.
func (c *Client) FetchSecret(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "secret", "fetch", id, mediaText, true)
}

// GetCertificate returns the certificate record for id as JSON.
func (c *Client) GetCertificate(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "cert", "get", id, mediaJSON, true)
}

// FetchCertificate returns the certificate PEM.
func (c *Client) FetchCertificate(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "cert", "fetch", id, mediaText, true)
}

// FetchCertificateBundle returns the certificate bundle (leaf plus private key).
func (c *Client) FetchCertificateBundle(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "cert", "fetch-bundle", id, mediaText, true)
}

// GetToken returns the token record for id as JSON.
func (c *Client) GetToken(ctx context.Context, id string) (string, error) {
	return c.do(ctx, "token", "get", id, mediaJSON, true)
}

func (c *Client) do(ctx context.Context, resource, action, id, media string, allowPrompt bool) (string, error) {
	if ctx == nil {
		return "", trustErr("context is required")
	}
	endpoint := c.endpoint(resource, action, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", wrapErr(err.Error(), err)
	}
	req.Header.Set(headerAPIToken, c.apiToken)
	req.Header.Set("Content-Type", media)
	req.Header.Set("Accept", media)
	if code := c.currentAccessCode(); code != "" {
		req.Header.Set(AccessCodeHeader, code)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", wrapErr(err.Error(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", wrapErr(err.Error(), err)
	}
	if resp.StatusCode == http.StatusOK {
		return string(body), nil
	}

	accessResponse := resp.Header.Get(AccessResponseHeader)
	stepUp := resp.StatusCode == AccessRequiredStatus || strings.TrimSpace(accessResponse) != ""
	if allowPrompt && c.prompt != nil && stepUp {
		prompt := strings.TrimSpace(string(body))
		if prompt == "" {
			prompt = "Please enter authentication code"
		}
		if err := c.PromptForAccessCode(prompt); err != nil {
			return "", err
		}
		return c.do(ctx, resource, action, id, media, false)
	}
	return "", parseHTTPError(resp.StatusCode, resp.Header.Get(headerBodyType), body)
}

func (c *Client) currentAccessCode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	code := strings.TrimSpace(c.accessCode)
	return code
}

func (c *Client) endpoint(resource, action, id string) string {
	base := strings.TrimRight(c.baseURL, "/")
	path := apiPrefix + "/" + resource + "/" + url.PathEscape(c.accountID) + "/" + action
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	return base + path
}

func parseHTTPError(status int, bodyType string, body []byte) error {
	message := strings.TrimSpace(string(body))
	switch bodyType {
	case bodyTypeError:
		if msg, ok := errorMessage(body); ok {
			message = msg
		}
	case bodyTypeCLError:
		if msg, ok := clErrorMessage(body); ok {
			message = msg
		}
	}
	if message == "" {
		message = "Unknown error"
	}
	return &Error{Message: message, HTTPStatus: status}
}

func errorMessage(body []byte) (string, bool) {
	var dto struct {
		Snake string `json:"error_message"`
		Camel string `json:"errorMessage"`
	}
	if err := strictUnmarshal(body, &dto); err != nil {
		return "", false
	}
	if strings.TrimSpace(dto.Snake) != "" {
		return dto.Snake, true
	}
	if strings.TrimSpace(dto.Camel) != "" {
		return dto.Camel, true
	}
	return "", false
}

func clErrorMessage(body []byte) (string, bool) {
	var dto struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := strictUnmarshal(body, &dto); err != nil {
		return "", false
	}
	if strings.TrimSpace(dto.Error.Message) == "" {
		return "", false
	}
	return dto.Error.Message, true
}

func strictUnmarshal(body []byte, dest any) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		return io.ErrUnexpectedEOF
	}
	return json.Unmarshal(body, dest)
}
