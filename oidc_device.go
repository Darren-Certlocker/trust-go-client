package trustclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// DeviceIssuer is the issuer (iss) for enrolled device JWTs.
	DeviceIssuer = "https://trust.certlocker.io/oidc/device"
	// DefaultDeviceTTL is the JWT lifetime used when minting for exchange.
	DefaultDeviceTTL = 5 * time.Minute
)

// DeviceOIDCConfig is the input for a DEVICE OIDC mint and Gateway exchange.
// Set PrivateKeyPath or PrivateKeyPEM. When both are set, the path is used.
// KeyID is required only when the enrolled principal has a key id.
type DeviceOIDCConfig struct {
	Audience       string
	DeviceID       string
	PrivateKeyPath string
	PrivateKeyPEM  string
	KeyID          string
	Issuer         string
	TTL            time.Duration
}

// AudienceForAccount returns the per-account audience
// https://trust.certlocker.io/oidc/<accountId>.
func AudienceForAccount(accountID string) (string, error) {
	if strings.TrimSpace(accountID) == "" {
		return "", fmt.Errorf("accountId is required")
	}
	return "https://trust.certlocker.io/oidc/" + strings.TrimSpace(accountID), nil
}

// DeviceSubject returns the JWT sub claim for a device id (device:<deviceId>).
func DeviceSubject(deviceID string) (string, error) {
	if strings.TrimSpace(deviceID) == "" {
		return "", fmt.Errorf("deviceId is required")
	}
	return "device:" + strings.TrimSpace(deviceID), nil
}

// LoadDevicePrivateKey reads a PKCS#8 Ed25519 private key from a PEM file.
func LoadDevicePrivateKey(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, trustErr("DEVICE private key path must not be blank")
	}
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, wrapErr("Failed to read DEVICE private key from "+path+": "+err.Error(), err)
	}
	return ParseDevicePrivateKey(string(raw))
}

// ParseDevicePrivateKey parses a PKCS#8 Ed25519 PEM (-----BEGIN PRIVATE KEY-----).
func ParseDevicePrivateKey(pemText string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(pemText) == "" {
		return nil, trustErr("DEVICE private key PEM is required")
	}
	if !strings.Contains(pemText, "BEGIN PRIVATE KEY") {
		return nil, trustErr("DEVICE private key must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----); OpenSSL/encrypted or OpenSSH formats are not supported")
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, trustErr("DEVICE private key must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----); OpenSSL/encrypted or OpenSSH formats are not supported")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, wrapErr("Invalid DEVICE private key PEM: "+err.Error(), err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, trustErr("DEVICE private key must be Ed25519 PKCS#8")
	}
	if len(ed) != ed25519.PrivateKeySize {
		return nil, trustErr("DEVICE private key must be Ed25519 PKCS#8")
	}
	return ed, nil
}

// MintDeviceJWT mints a short-lived device JWT (alg=EdDSA) from cfg.
func MintDeviceJWT(cfg DeviceOIDCConfig) (string, error) {
	if err := cfg.validate(); err != nil {
		return "", err
	}
	var key ed25519.PrivateKey
	var err error
	if strings.TrimSpace(cfg.PrivateKeyPath) != "" {
		key, err = LoadDevicePrivateKey(cfg.PrivateKeyPath)
	} else {
		key, err = ParseDevicePrivateKey(cfg.PrivateKeyPEM)
	}
	if err != nil {
		return "", err
	}
	issuer := cfg.Issuer
	if strings.TrimSpace(issuer) == "" {
		issuer = DeviceIssuer
	}
	return signDeviceJWT(issuer, cfg.Audience, cfg.DeviceID, key, cfg.KeyID, cfg.ttl())
}

func (cfg DeviceOIDCConfig) validate() error {
	if strings.TrimSpace(cfg.Audience) == "" {
		return fmt.Errorf("audience must not be blank")
	}
	if strings.TrimSpace(cfg.DeviceID) == "" {
		return fmt.Errorf("deviceId must not be blank")
	}
	if strings.TrimSpace(cfg.PrivateKeyPath) == "" && strings.TrimSpace(cfg.PrivateKeyPEM) == "" {
		return fmt.Errorf("privateKeyPath or privateKeyPem is required")
	}
	return nil
}

func (cfg DeviceOIDCConfig) ttl() time.Duration {
	if cfg.TTL <= 0 {
		return DefaultDeviceTTL
	}
	if cfg.TTL < time.Minute {
		return time.Minute
	}
	return cfg.TTL
}

type deviceHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

type deviceClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	JTI      string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	DeviceID string `json:"device_id"`
}

func signDeviceJWT(issuer, audience, deviceID string, key ed25519.PrivateKey, keyID string, ttl time.Duration) (string, error) {
	if key == nil {
		return "", trustErr("privateKey is required")
	}
	if strings.TrimSpace(issuer) == "" {
		return "", trustErr("DEVICE issuer is required")
	}
	if strings.TrimSpace(audience) == "" {
		return "", trustErr("DEVICE audience is required")
	}
	if strings.TrimSpace(deviceID) == "" {
		return "", trustErr("deviceId is required")
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	subject, err := DeviceSubject(deviceID)
	if err != nil {
		return "", trustErr(err.Error())
	}
	jti, err := newJTI()
	if err != nil {
		return "", wrapErr("Failed to mint DEVICE JWT: "+err.Error(), err)
	}
	now := time.Now().UTC()
	header := deviceHeader{Alg: "EdDSA"}
	if strings.TrimSpace(keyID) != "" {
		header.Kid = strings.TrimSpace(keyID)
	}
	claims := deviceClaims{
		Issuer:   strings.TrimSpace(issuer),
		Audience: strings.TrimSpace(audience),
		Subject:  subject,
		JTI:      jti,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(ttl).Unix(),
		DeviceID: strings.TrimSpace(deviceID),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", wrapErr("Failed to mint DEVICE JWT: "+err.Error(), err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", wrapErr("Failed to mint DEVICE JWT: "+err.Error(), err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
