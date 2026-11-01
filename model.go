package trustclient

import (
	"strings"
	"time"
)

// AssetStatus is the lifecycle status of a Trust asset.
type AssetStatus string

const (
	AssetStatusActive    AssetStatus = "ACTIVE"
	AssetStatusSuspended AssetStatus = "SUSPENDED"
	AssetStatusExpired   AssetStatus = "EXPIRED"
	AssetStatusRevoked   AssetStatus = "REVOKED"
)

// IsActive reports whether the asset is active.
func (s AssetStatus) IsActive() bool { return s == AssetStatusActive }

// CanSuspend reports whether the asset can be suspended.
func (s AssetStatus) CanSuspend() bool { return s == AssetStatusActive }

// CanRevoke reports whether the asset can be revoked.
func (s AssetStatus) CanRevoke() bool { return s != AssetStatusRevoked }

// CanResume reports whether a suspended asset can be resumed.
func (s AssetStatus) CanResume() bool { return s == AssetStatusSuspended }

// CanRenew reports whether the asset can be renewed.
func (s AssetStatus) CanRenew() bool {
	return s == AssetStatusActive || s == AssetStatusExpired
}

// CanRotate reports whether the asset can be rotated.
func (s AssetStatus) CanRotate() bool {
	return s == AssetStatusActive || s == AssetStatusExpired
}

// AssetType is the kind of asset stored in Trust.
type AssetType string

const (
	AssetTypeHost        AssetType = "HOST"
	AssetTypeSecret      AssetType = "SECRET"
	AssetTypeCertificate AssetType = "CERTIFICATE"
	AssetTypeToken       AssetType = "TOKEN"
	AssetTypeBastion     AssetType = "BASTION"
	AssetTypeProbe       AssetType = "PROBE"
	AssetTypeAgent       AssetType = "AGENT"
	AssetTypeACMEClient  AssetType = "ACME_CLIENT"
	AssetTypeDNSClient   AssetType = "DNS_CLIENT"
	AssetTypeAutomation  AssetType = "AUTOMATION"
	AssetTypeChannel     AssetType = "CHANNEL"
)

// Asset holds the fields shared by secrets, certificates, and tokens.
type Asset struct {
	ID          string      `json:"id,omitempty"`
	AccountID   string      `json:"account_id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Status      AssetStatus `json:"status,omitempty"`
	Groups      StringList  `json:"groups,omitempty"`
	CreatedBy   string      `json:"created_by,omitempty"`
	UpdatedBy   string      `json:"updated_by,omitempty"`
	DateCreated *Time       `json:"date_created,omitempty"`
	DateUpdated *Time       `json:"date_updated,omitempty"`
	LockedBy    string      `json:"locked_by,omitempty"`
	DateLocked  *Time       `json:"date_locked,omitempty"`
}

// SecretType is the kind of secret stored in Trust.
type SecretType string

const (
	SecretTypePrivateKey    SecretType = "PRIVATE_KEY"
	SecretTypePEM           SecretType = "PEM"
	SecretTypePassword      SecretType = "PASSWORD"
	SecretTypeCredentials   SecretType = "CREDENTIALS"
	SecretTypeConfiguration SecretType = "CONFIGURATION"
)

// HasAlgo reports whether this secret type carries a key algorithm.
func (t SecretType) HasAlgo() bool {
	return t == SecretTypePrivateKey || t == SecretTypePEM
}

// SecretKeyAlgorithm is the public-key algorithm for PEM and private-key secrets.
type SecretKeyAlgorithm string

const (
	SecretKeyAlgorithmRSA     SecretKeyAlgorithm = "RSA"
	SecretKeyAlgorithmECDSA   SecretKeyAlgorithm = "ECDSA"
	SecretKeyAlgorithmED25519 SecretKeyAlgorithm = "ED25519"
)

// Crypto is the key algorithm and size shared by PEM and private-key secrets.
type Crypto struct {
	KeyAlgorithm SecretKeyAlgorithm `json:"key_algorithm,omitempty"`
	KeySize      string             `json:"key_size,omitempty"`
}

// PQReady reports whether the key algorithm is Ed25519.
func (c Crypto) PQReady() bool {
	return c.KeyAlgorithm == SecretKeyAlgorithmED25519
}

// Secret is the secret record returned by get.
type Secret struct {
	Asset
	SecretType SecretType `json:"secret_type,omitempty"`
	Secret     string     `json:"secret,omitempty"`
	Version    int        `json:"version,omitempty"`
}

// PEM is a PEM secret, including the key material. Fetch returns this as JSON.
type PEM struct {
	Crypto
	Username string `json:"username,omitempty"`
	Key      string `json:"key,omitempty"`
}

// PrivateKey is a private-key secret. Fetch returns this as JSON.
type PrivateKey struct {
	Crypto
	Key string `json:"key,omitempty"`
}

// Credentials is a username and password secret. Fetch returns this as JSON.
type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Password is a password secret. The value is the raw fetch body.
type Password struct {
	Password string
}

// Configuration is a free-form configuration secret. The value is the raw fetch body.
type Configuration struct {
	Secret string
}

// CertificateValidation is how a certificate was validated.
type CertificateValidation string

const (
	CertificateValidationDV      CertificateValidation = "DV"
	CertificateValidationOV      CertificateValidation = "OV"
	CertificateValidationEV      CertificateValidation = "EV"
	CertificateValidationSS      CertificateValidation = "SS"
	CertificateValidationUnknown CertificateValidation = "UNKNOWN"
)

// Description returns the display name of this validation level.
func (v CertificateValidation) Description() string {
	switch v {
	case CertificateValidationDV:
		return "Domain Validated"
	case CertificateValidationOV:
		return "Organization Validated"
	case CertificateValidationEV:
		return "Extended Validation"
	case CertificateValidationSS:
		return "Self Signed"
	case CertificateValidationUnknown:
		return "Unknown"
	default:
		return ""
	}
}

// Certificate is the certificate record returned by get.
type Certificate struct {
	Asset
	Expires               *Time                 `json:"expires,omitempty"`
	PrimaryDomain         string                `json:"primary_domain,omitempty"`
	SANDomains            StringList            `json:"san_domains,omitempty"`
	NotBefore             *Time                 `json:"not_before,omitempty"`
	Entries               int                   `json:"entries,omitempty"`
	SerialNumber          string                `json:"serial_number,omitempty"`
	PublicKeyAlgo         string                `json:"public_key_algo,omitempty"`
	MerkleTreeCert        bool                  `json:"merkle_tree_cert,omitempty"`
	IssuerCN              string                `json:"issuer_cn,omitempty"`
	IssuerO               string                `json:"issuer_o,omitempty"`
	FingerprintSHA256     string                `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA1       string                `json:"fingerprint_sha1,omitempty"`
	PublicCert            string                `json:"public_cert,omitempty"`
	CertificateProperties string                `json:"certificate_properties,omitempty"`
	PrivateKey            string                `json:"private_key,omitempty"`
	CertValidation        CertificateValidation `json:"cert_validation,omitempty"`
	LinkID                string                `json:"link_id,omitempty"`
	PercentRemaining      int                   `json:"percent_remaining,omitempty"`
}

// TokenType is what a token grants access to.
type TokenType string

const (
	TokenTypeCertificate TokenType = "CERTIFICATE"
	TokenTypeHost        TokenType = "HOST"
	TokenTypeBastion     TokenType = "BASTION"
	TokenTypeSecret      TokenType = "SECRET"
	TokenTypeRoot        TokenType = "ROOT"
	TokenTypeMCP         TokenType = "MCP"
	TokenTypeWildcard    TokenType = "WILDCARD"
)

// Protocol is a protocol a token is allowed to use.
type Protocol string

const (
	ProtocolSSH   Protocol = "SSH"
	ProtocolSFTP  Protocol = "SFTP"
	ProtocolHTTPS Protocol = "HTTPS"
	ProtocolACME  Protocol = "ACME"
	ProtocolMCP   Protocol = "MCP"
	ProtocolRDP   Protocol = "RDP"
	ProtocolVNC   Protocol = "VNC"
)

// IsSSHFamily reports whether this protocol is SSH or SFTP.
func (p Protocol) IsSSHFamily() bool {
	return p == ProtocolSSH || p == ProtocolSFTP
}

// ProtocolList decodes a JSON string or an array of protocol names.
type ProtocolList []Protocol

// UnmarshalJSON accepts a JSON string or an array of protocol names.
func (p *ProtocolList) UnmarshalJSON(b []byte) error {
	items, err := flexStrings(b)
	if err != nil {
		return err
	}
	if items == nil {
		*p = nil
		return nil
	}
	out := make(ProtocolList, len(items))
	for i, item := range items {
		out[i] = Protocol(item)
	}
	*p = out
	return nil
}

// Token is the token record returned by get.
type Token struct {
	Asset
	SingleUse        bool         `json:"single_use,omitempty"`
	Protocols        ProtocolList `json:"protocols,omitempty"`
	TokenType        TokenType    `json:"token_type,omitempty"`
	Hosts            StringList   `json:"hosts,omitempty"`
	GroupAccess      StringList   `json:"group_access,omitempty"`
	SecretID         string       `json:"secret_id,omitempty"`
	AccessCode       string       `json:"access_code,omitempty"`
	BastionID        string       `json:"bastion_id,omitempty"`
	CertID           string       `json:"cert_id,omitempty"`
	AutoRotate       bool         `json:"auto_rotate,omitempty"`
	CIDR             string       `json:"cidr,omitempty"`
	UserID           string       `json:"user_id,omitempty"`
	AgentID          string       `json:"agent_id,omitempty"`
	StartTime        *Time        `json:"start_time,omitempty"`
	PercentRemaining int          `json:"percent_remaining,omitempty"`
}

// ParseTime parses a Trust timestamp string.
func ParseTime(value string) (time.Time, error) {
	return parseTrustTime(value)
}

func stringField(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
