package trustclient

import "context"

// Service is typed access to Trust secrets, certificates, and tokens.
//
// Get methods return the asset record. Fetch methods return the asset contents.
// Closing the service closes the underlying [Client].
//
// An asset token is an x-api-token assigned to one secret. Pass an empty id to
// FetchSecret to read that secret. Pass an id when the token is not assigned
// to a single asset. Certificate and token Gateway routes require an id.
type Service struct {
	client *Client
}

// NewService wraps an existing client. Close closes that client.
func NewService(client *Client) *Service {
	return &Service{client: client}
}

// Client returns the underlying client.
func (s *Service) Client() *Client { return s.client }

// Close closes the underlying client.
func (s *Service) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

// SetAccessCode sets a 2FA / access code for subsequent requests.
func (s *Service) SetAccessCode(accessCode string) {
	s.client.SetAccessCode(accessCode)
}

// FetchSecret returns the contents of the secret.
// An empty id selects the secret assigned to the API token.
func (s *Service) FetchSecret(ctx context.Context, id string) (string, error) {
	return s.client.FetchSecret(ctx, id)
}

// GetSecret returns the secret record.
// An empty id calls get with no asset segment.
func (s *Service) GetSecret(ctx context.Context, id string) (*Secret, error) {
	body, err := s.client.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return decodeJSON[Secret](body)
}

// GetSecretAsPEM returns the secret contents as a PEM secret.
func (s *Service) GetSecretAsPEM(ctx context.Context, id string) (*PEM, error) {
	return fetchAs[PEM](s, ctx, id)
}

// GetSecretAsConfiguration returns the secret contents as a configuration secret.
func (s *Service) GetSecretAsConfiguration(ctx context.Context, id string) (Configuration, error) {
	body, err := s.client.FetchSecret(ctx, id)
	if err != nil {
		return Configuration{}, err
	}
	return Configuration{Secret: body}, nil
}

// GetSecretAsPrivateKey returns the secret contents as a private key.
func (s *Service) GetSecretAsPrivateKey(ctx context.Context, id string) (*PrivateKey, error) {
	return fetchAs[PrivateKey](s, ctx, id)
}

// GetSecretAsPassword returns the secret contents as a password.
func (s *Service) GetSecretAsPassword(ctx context.Context, id string) (Password, error) {
	body, err := s.client.FetchSecret(ctx, id)
	if err != nil {
		return Password{}, err
	}
	return Password{Password: body}, nil
}

// GetSecretAsCredentials returns the secret contents as credentials.
func (s *Service) GetSecretAsCredentials(ctx context.Context, id string) (*Credentials, error) {
	return fetchAs[Credentials](s, ctx, id)
}

func fetchAs[T any](s *Service, ctx context.Context, id string) (*T, error) {
	body, err := s.client.FetchSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return decodeJSON[T](body)
}

// GetCertificate returns the certificate record.
// This calls the JSON get route. Use FetchCertificate for the PEM.
func (s *Service) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	body, err := s.client.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	return decodeJSON[Certificate](body)
}

// FetchCertificate returns the certificate PEM.
func (s *Service) FetchCertificate(ctx context.Context, id string) (string, error) {
	return s.client.FetchCertificate(ctx, id)
}

// FetchCertificateBundle returns the certificate bundle.
func (s *Service) FetchCertificateBundle(ctx context.Context, id string) (string, error) {
	return s.client.FetchCertificateBundle(ctx, id)
}

// GetToken returns the token record.
func (s *Service) GetToken(ctx context.Context, id string) (*Token, error) {
	body, err := s.client.GetToken(ctx, id)
	if err != nil {
		return nil, err
	}
	return decodeJSON[Token](body)
}
