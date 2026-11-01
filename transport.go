package trustclient

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RedirectPolicy controls how the HTTP client follows redirects.
// The default is [RedirectNever], matching java.net.http.HttpClient.
type RedirectPolicy int

const (
	// RedirectNever does not follow redirects.
	RedirectNever RedirectPolicy = iota
	// RedirectNormal follows redirects except from HTTPS to HTTP.
	RedirectNormal
	// RedirectAlways follows redirects, including HTTPS to HTTP.
	RedirectAlways
)

// HTTPVersion is the preferred HTTP protocol version.
type HTTPVersion int

const (
	// HTTPVersionDefault lets the transport negotiate HTTP/2 when the server supports it.
	HTTPVersionDefault HTTPVersion = iota
	// HTTP1 forces HTTP/1.1.
	HTTP1
	// HTTP2 prefers HTTP/2.
	HTTP2
)

type transportConfig struct {
	connectTimeout time.Duration
	requestTimeout time.Duration
	redirects      RedirectPolicy
	version        HTTPVersion
	proxy          *url.URL
	noProxy        bool
	tlsConfig      *tls.Config
	jar            http.CookieJar
	localAddr      net.Addr
}

func buildHTTPClient(cfg transportConfig) (*http.Client, error) {
	connect := cfg.connectTimeout
	if connect <= 0 {
		connect = DefaultConnectTimeout
	}
	dialer := &net.Dialer{
		Timeout:   connect,
		KeepAlive: 30 * time.Second,
		LocalAddr: cfg.localAddr,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     cfg.version != HTTP1,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       cfg.tlsConfig,
	}
	if cfg.version == HTTP1 {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	switch {
	case cfg.noProxy:
		transport.Proxy = nil
	case cfg.proxy != nil:
		transport.Proxy = http.ProxyURL(cfg.proxy)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.requestTimeout,
		Jar:       cfg.jar,
	}
	switch cfg.redirects {
	case RedirectAlways:
		client.CheckRedirect = limitRedirects(false)
	case RedirectNormal:
		client.CheckRedirect = limitRedirects(true)
	default:
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client, nil
}

func limitRedirects(blockHTTPSDowngrade bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if blockHTTPSDowngrade && len(via) > 0 {
			prev := via[len(via)-1]
			if prev.URL != nil && req.URL != nil &&
				strings.EqualFold(prev.URL.Scheme, "https") &&
				strings.EqualFold(req.URL.Scheme, "http") {
				return errors.New("redirect from https to http is not allowed")
			}
		}
		return nil
	}
}

func newSimpleClient(connect time.Duration) *http.Client {
	if connect <= 0 {
		connect = DefaultConnectTimeout
	}
	client, err := buildHTTPClient(transportConfig{connectTimeout: connect})
	if err != nil {
		dialer := &net.Dialer{Timeout: connect}
		return &http.Client{
			Timeout: connect,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return client
}
