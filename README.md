<img align="right" alt="Certlocker" src="https://certlocker.io/logo-white-32.png" width="32" height="32">

# Trust Go Client

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Go client for [Certlocker Trust](https://trust.certlocker.io). It reads secrets, certificates, and tokens over the Gateway API, and it can sign in with a UI-minted API token or by exchanging an OIDC identity token.

The client uses only the Go standard library. It needs **Go 1.22** or later.

Feature set matches [trust-java-client](https://github.com/Darren-Certlocker/trust-java-client) 1.0.4: `get` returns the asset record, `fetch` returns the asset contents.

## Install

```bash
go get github.com/Darren-Certlocker/trust-go-client@latest
```

```go
import "github.com/Darren-Certlocker/trust-go-client"
```

The package name is `trustclient`.

For a local checkout:

```bash
go mod edit -replace github.com/Darren-Certlocker/trust-go-client=/path/to/trust-go-client
go get github.com/Darren-Certlocker/trust-go-client@v0.0.0
```

## Features

- **Secrets** — get the record; fetch the contents; typed readers for PEM, configuration, password, credentials, and private key
- **Certificates** — get the record; fetch the leaf PEM; fetch the bundle (certificate plus private key)
- **Tokens** — get the record
- **Auth** — UI-minted static API token; ambient OIDC (GitHub Actions, GCP, Azure, Azure DevOps); enrolled device OIDC (Ed25519 / `EdDSA`); optional mint type `SECRET`, `CERTIFICATE`, or `MCP`; 2FA via `AuthCodePrompt`
- **Paths** — Gateway calls include `{accountId}`. The path account must match the token’s account

Every call takes a `context.Context`. Cancel the context to stop an in-flight request.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/Darren-Certlocker/trust-go-client"
)

func main() {
    ctx := context.Background()

    service, err := trustclient.NewBuilder().
        URL("https://trust.certlocker.io").
        AccountID("<accountId>").
        APIToken("<ui-minted-token-id>").
        BuildService(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer service.Close()

    secret, err := service.GetSecret(ctx, "mvusgvkv5")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(secret.Name, secret.SecretType, secret.Status)
}
```

`Build` returns a `*Client` for raw response bodies. `BuildService` returns a `*Service` that decodes those bodies. `Service.Close` closes the underlying client. `Client.Close` closes idle connections when the builder created the HTTP client. A client you pass to `HTTPClient` stays open.

## Authentication

Prefer federated OIDC for CI and machines. Use a UI-minted `SECRET` token for break-glass and local human use.

The audience for GitHub, GCP, Azure, and device OIDC is per account:

```text
https://trust.certlocker.io/oidc/<accountId>
```

```go
audience, err := trustclient.AudienceForAccount(accountID)
```

Azure DevOps uses ADO’s fixed audience `api://AzureADTokenExchange`. Trust matches that principal by issuer and `sub`.

### Static API token

```go
client, err := trustclient.NewBuilder().
    URL("https://trust.certlocker.io").
    AccountID("<accountId>").
    APIToken("<ui-minted-token-id>").
    Build(ctx)
```

The token is sent as `x-api-token`. Gateway asset paths look like `/rest/api/v1/secret/{accountId}/fetch`. The path `accountId` must match the token’s account.

`URL` must be an absolute `http` or `https` URL. Surrounding whitespace is ignored. A base URL may include a path prefix, which is how a local Gateway is usually addressed:

```go
trustclient.NewBuilder().
    URL("http://localhost:8080/gateway").
    AccountID(accountID).
    APIToken(token)
```

That calls `http://localhost:8080/gateway/rest/api/v1/...`.

### Ambient OIDC

`FromAmbientOIDC` and `PreferAmbientOIDC(true)` pick the first available ambient provider: GitHub Actions, then GCP, then Azure, then Azure DevOps. When `AccountID` is left unset, it is taken from the exchange response.

```go
client, err := trustclient.FromAmbientOIDC(
    ctx,
    "https://trust.certlocker.io",
    "https://trust.certlocker.io/oidc/<accountId>",
)
```

Or on the builder:

```go
client, err := trustclient.NewBuilder().
    URL("https://trust.certlocker.io").
    OIDCAudience("https://trust.certlocker.io/oidc/<accountId>").
    PreferAmbientOIDC(true).
    Build(ctx)
```

If ambient exchange fails and `APIToken` is also set, that static token is kept. If exchange fails and no API token is set, `Build` returns an error.

| Provider | Detection | Needs Trust audience |
| --- | --- | --- |
| GitHub Actions | `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (`permissions: id-token: write`) | Yes |
| GCP | GCE / GKE / Cloud Run metadata (`K_SERVICE` or `GCE_METADATA_HOST`, otherwise a short metadata probe) | Yes |
| Azure | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`, otherwise IMDS | Yes |
| Azure DevOps | `SYSTEM_OIDCREQUESTURI` + `SYSTEM_ACCESSTOKEN` | No (fixed ADO audience) |

Availability checks:

```go
trustclient.GitHubActionsAvailable()
trustclient.GCPAvailable()
trustclient.AzureAvailable()
trustclient.AzureDevOpsAvailable()
```

Optional Azure user-assigned identity: `AZURE_CLIENT_ID`.

Optional Azure DevOps service connection, sent as `serviceConnectionId`: `AZURESUBSCRIPTION_SERVICE_CONNECTION_ID` or `SYSTEM_OIDC_SERVICE_CONNECTION_ID`. Map `System.AccessToken` into the job as `SYSTEM_ACCESSTOKEN`.

### Explicit provider exchange

Exchange first, then build a client with the minted token:

```go
trustURL := "https://trust.certlocker.io"
audience := "https://trust.certlocker.io/oidc/<accountId>"

gha, err := trustclient.ExchangeGitHubActions(ctx, trustURL, audience, "")
if err != nil {
    log.Fatal(err)
}

client, err := trustclient.NewBuilder().
    URL(trustURL).
    APIToken(gha.TokenID).
    AccountID(gha.AccountID).
    Build(ctx)
```

The other providers are the same shape:

```go
gcp, err := trustclient.ExchangeGCP(ctx, trustURL, audience, "")
azure, err := trustclient.ExchangeAzure(ctx, trustURL, audience, "")
ado, err := trustclient.ExchangeAzureDevOps(ctx, trustURL, "")
```

An empty mint type uses the matched principal’s `defaultTokenType` (usually `SECRET`).

`ExchangeResult` fields:

| Field | Meaning |
| --- | --- |
| `TokenID` | Value for `x-api-token` |
| `ExpiresAt` | Expiry, or nil when the response omitted it |
| `TokenType` | `SECRET`, `CERTIFICATE`, or `MCP` |
| `AccountID` | Tenant for Gateway paths |
| `PrincipalID` | OIDC principal that minted the token |

The exchange call is `POST /rest/api/v1/oidc/exchange`. The JSON body carries `id_token` and, when set, `token_type`. The client also sends the camelCase names `idToken` and `tokenType`, and it accepts either naming on the response.

You can fetch the raw provider JWT without exchanging it:

```go
jwt, err := trustclient.RequestGitHubActionsIDToken(ctx, audience)
jwt, err = trustclient.RequestGCPIDToken(ctx, audience)
jwt, err = trustclient.RequestAzureIDToken(ctx, audience)
jwt, err = trustclient.RequestAzureDevOpsIDToken(ctx)
```

GCP reads `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=…&format=full` with `Metadata-Flavor: Google`. Override the host with `GCE_METADATA_HOST`.

Azure tries App Service identity (`IDENTITY_ENDPOINT`, header `X-IDENTITY-HEADER`, `api-version=2019-08-01`) and otherwise IMDS `http://169.254.169.254/metadata/identity/oauth2/token` (`api-version=2018-02-01`, header `Metadata: true`). The Trust audience is the `resource` query parameter.

### Device OIDC

Mint a short-lived Ed25519 / `EdDSA` JWT from the PKCS#8 private key downloaded at enroll, then exchange it for a Trust token. Keep the private key on the machine.

```go
home, err := os.UserHomeDir()
if err != nil {
    log.Fatal(err)
}
client, err := trustclient.FromDeviceOIDC(ctx, "https://trust.certlocker.io", trustclient.DeviceOIDCConfig{
    Audience:       "https://trust.certlocker.io/oidc/<accountId>",
    DeviceID:       "laptop-1",
    PrivateKeyPath: filepath.Join(home, ".trust", "device.pem"),
    KeyID:          "device-abc123", // required when the principal enrolled a keyId
})
```

`os` and `path/filepath` are the extra imports for that snippet.

`PrivateKeyPEM` may be set instead of `PrivateKeyPath`. When both are set, the file is used.

Shorter form when the key is a file:

```go
client, err := trustclient.FromDeviceOIDCFile(
    ctx,
    "https://trust.certlocker.io",
    "https://trust.certlocker.io/oidc/<accountId>",
    "laptop-1",
    filepath.Join(home, ".trust", "device.pem"),
    "device-abc123",
)
```

Or mint the JWT yourself and exchange it:

```go
jwt, err := trustclient.MintDeviceJWT(trustclient.DeviceOIDCConfig{
    Audience:      audience,
    DeviceID:      "laptop-1",
    PrivateKeyPEM: pem,
    KeyID:         "device-abc123",
    TTL:           5 * time.Minute,
})
client, err = trustclient.FromIDToken(ctx, "https://trust.certlocker.io", jwt)
```

Claim shape:

| Claim | Value |
| --- | --- |
| `iss` | `https://trust.certlocker.io/oidc/device` (`DeviceIssuer`; override with `DeviceOIDCConfig.Issuer`) |
| `aud` | `https://trust.certlocker.io/oidc/<accountId>` |
| `sub` | `device:<deviceId>` (`DeviceSubject`) |
| `device_id` | enrolled device id |
| `kid` | optional; must match the enrolled `keyId` when that field is set |
| `alg` | `EdDSA` |

`TTL` defaults to 5 minutes (`DefaultDeviceTTL`). A positive TTL below one minute is raised to one minute. The PEM must be PKCS#8 (`-----BEGIN PRIVATE KEY-----`). OpenSSH and encrypted PEMs are rejected.

```go
key, err := trustclient.LoadDevicePrivateKey(path)
key, err = trustclient.ParseDevicePrivateKey(pemText)
```

### Mint types: SECRET, CERTIFICATE, MCP

Pass `TokenTypeSecret`, `TokenTypeCertificate`, or `TokenTypeMCP` when the principal allows that type. An empty `TokenType` uses the principal default. `FromAmbientOIDC`, `FromDeviceOIDC`, and `FromIDToken` use the default.

```go
secret, err := trustclient.ExchangeGitHubActions(ctx, trustURL, audience, trustclient.TokenTypeSecret)
cert, err := trustclient.ExchangeGCP(ctx, trustURL, audience, trustclient.TokenTypeCertificate)
mcp, err := trustclient.ExchangeAzure(ctx, trustURL, audience, trustclient.TokenTypeMCP)

deviceMCP, err := trustclient.ExchangeDeviceOIDC(ctx, trustURL, trustclient.DeviceOIDCConfig{
    Audience:       audience,
    DeviceID:       "laptop-1",
    PrivateKeyPath: filepath.Join(home, ".trust", "device.pem"),
}, trustclient.TokenTypeMCP)

fmt.Println(secret.TokenType) // SECRET, CERTIFICATE, or MCP

client, err := trustclient.NewBuilder().
    URL(trustURL).
    APIToken(secret.TokenID).
    AccountID(secret.AccountID).
    Build(ctx)
```

`ExchangeIDToken` is the same exchange for a JWT you already hold:

```go
result, err := trustclient.ExchangeIDToken(ctx, trustURL, jwt, trustclient.TokenTypeMCP)
```

### 2FA / access-code step-up

User-bound tokens may require an access code. On HTTP 401, or when the response carries `x-access-response` (`ACCESS_CODE`, `OTP`, or `EMAIL`), the client shows the response body as the prompt, then retries the call once with `x-access-code`.

```go
client, err := trustclient.NewBuilder().
    URL("https://trust.certlocker.io").
    AccountID("<accountId>").
    APIToken("<user-bound-token>").
    AuthCodePrompt(trustclient.ConsoleAuthCodePrompt).
    Build(ctx)
```

`ConsoleAuthCodePrompt` reads a line from stdin. A custom prompt is any function:

```go
trustclient.NewBuilder().
    AuthCodePrompt(func(reason string) (string, error) {
        fmt.Println(reason)
        var code string
        _, err := fmt.Scanln(&code)
        return code, err
    })
```

Set a code you already have, for later requests:

```go
client.SetAccessCode("123456")
service.SetAccessCode("123456")
```

Constants: `AccessCodeHeader` (`x-access-code`), `AccessResponseHeader` (`x-access-response`), `AccessRequiredStatus` (401).

## Reading assets

`Service` decodes records and typed secret payloads. `Client` returns the raw body.

Pass an empty id to `FetchSecret` when the API token is assigned to one secret. That calls:

```text
GET /rest/api/v1/secret/{accountId}/fetch
```

`GetSecret`, certificate calls, and `GetToken` take the asset id. The Gateway routes for those calls include it.

| Call | Route | Body |
| --- | --- | --- |
| `GetSecret` | `GET /rest/api/v1/secret/{accountId}/get/{secretId}` | JSON secret record |
| `FetchSecret` | `GET /rest/api/v1/secret/{accountId}/fetch[/{secretId}]` | secret contents |
| `GetCertificate` | `GET /rest/api/v1/cert/{accountId}/get/{certificateId}` | JSON certificate record |
| `FetchCertificate` | `GET /rest/api/v1/cert/{accountId}/fetch/{certificateId}` | leaf PEM |
| `FetchCertificateBundle` | `GET /rest/api/v1/cert/{accountId}/fetch-bundle/{certificateId}` | PEM bundle |
| `GetToken` | `GET /rest/api/v1/token/{accountId}/get/{tokenId}` | JSON token record |

Requests send `x-api-token`, plus `Content-Type` and `Accept` of `application/json` for get and `text/plain` for fetch.

```go
service, err := trustclient.NewBuilder().
    URL("https://trust.certlocker.io").
    AccountID("<accountId>").
    APIToken("<token>").
    BuildService(ctx)
if err != nil {
    log.Fatal(err)
}
defer service.Close()

// Records.
secret, err := service.GetSecret(ctx, "mvusgvkv5")
certificate, err := service.GetCertificate(ctx, "certId")
token, err := service.GetToken(ctx, "tokenId")

// Contents.
config, err := service.GetSecretAsConfiguration(ctx, "mvusgvkv5")
pemSecret, err := service.GetSecretAsPEM(ctx, "b5fqj6c8d")
password, err := service.GetSecretAsPassword(ctx, "v5q7pspif")
credentials, err := service.GetSecretAsCredentials(ctx, "17bu1p62uq")
privateKey, err := service.GetSecretAsPrivateKey(ctx, "k8m7c8pps")

leaf, err := service.FetchCertificate(ctx, "certId")
bundle, err := service.FetchCertificateBundle(ctx, "certId")

// Token assigned to one secret. Trust selects it, so no id is sent.
assigned, err := service.FetchSecret(ctx, "")
assignedPassword, err := service.GetSecretAsPassword(ctx, "")
```

Raw bodies, if you want to decode them yourself:

```go
recordJSON, err := client.GetSecret(ctx, "mvusgvkv5")
contents, err := client.FetchSecret(ctx, "mvusgvkv5")
pemLeaf, err := client.FetchCertificate(ctx, "certId")
pemBundle, err := client.FetchCertificateBundle(ctx, "certId")
tokenJSON, err := client.GetToken(ctx, "tokenId")
```

### Secret payloads

`GetSecret` decodes the record. `SecretType` is `PRIVATE_KEY`, `PEM`, `PASSWORD`, `CREDENTIALS`, or `CONFIGURATION`. `HasAlgo` is true for `PRIVATE_KEY` and `PEM`.

Password and configuration fetches are the raw body:

```go
type Password struct { Password string }
type Configuration struct { Secret string }
```

PEM, credentials, and private key fetches are JSON.

```json
{"username":"ubuntu","key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n","key_algorithm":"ED25519","key_size":"256"}
```

```json
{"username":"alice","password":"s3cret"}
```

```json
{"key":"-----BEGIN PRIVATE KEY-----\n...\n","key_algorithm":"RSA","key_size":"2048"}
```

`key_algorithm` is `RSA`, `ECDSA`, or `ED25519`. `PQReady` is true for `ED25519`.

```go
if pemSecret.PQReady() {
    fmt.Println(pemSecret.KeyAlgorithm, pemSecret.KeySize)
}
fmt.Println(credentials.Username, password.Password, privateKey.Key)
fmt.Println(config.Secret)
```

Asset records use snake_case. Shared fields live on `Asset`: `ID`, `AccountID`, `Name`, `Description`, `Status`, `Groups`, `CreatedBy`, `UpdatedBy`, `DateCreated`, `DateUpdated`, `LockedBy`, `DateLocked`.

`AssetStatus` is `ACTIVE`, `SUSPENDED`, `EXPIRED`, or `REVOKED`.

```go
secret.Status.IsActive()
secret.Status.CanSuspend()  // ACTIVE
secret.Status.CanRevoke()   // any status other than REVOKED
secret.Status.CanResume()   // SUSPENDED
secret.Status.CanRenew()    // ACTIVE or EXPIRED
secret.Status.CanRotate()   // ACTIVE or EXPIRED
```

Timestamps are UTC. The usual wire format is `2006-01-02T15:04:05.000Z`. `ParseTime` accepts that form, RFC3339, and a local date-time interpreted as UTC.

### Certificates

`GetCertificate` returns the record (`primary_domain`, `san_domains`, `serial_number`, fingerprints, `cert_validation`, and the other `Certificate` fields). `FetchCertificate` returns the leaf PEM. `FetchCertificateBundle` returns the bundle.

`CertificateValidation` is `DV`, `OV`, `EV`, `SS`, or `UNKNOWN`. `Description` returns "Domain Validated", "Organization Validated", "Extended Validation", "Self Signed", or "Unknown".

```go
fmt.Println(certificate.PrimaryDomain, certificate.CertValidation.Description())
fmt.Println(leaf)
fmt.Println(bundle)
```

`san_domains` may be a JSON array or a single string.

### Tokens

```go
fmt.Println(token.TokenType, token.Protocols, token.SecretID, token.CertID)
fmt.Println(token.Hosts, token.SingleUse, token.AutoRotate)
for _, p := range token.Protocols {
    if p.IsSSHFamily() { // SSH or SFTP
        fmt.Println(p)
    }
}
```

`TokenType` on a record is `CERTIFICATE`, `HOST`, `BASTION`, `SECRET`, `ROOT`, `MCP`, or `WILDCARD`.

`Protocol` is `SSH`, `SFTP`, `HTTPS`, `ACME`, `MCP`, `RDP`, or `VNC`. A single string or an array both decode.

## Errors

Gateway failures return `*trustclient.Error`. `Error()` is the Trust message. `HTTPStatus` is set for HTTP error responses. `HasTrustError` reports that case. `Unwrap` returns a transport or decode cause when there is one.

`x-body-type: certlocker.gateway.api.model.ErrorDTO` is read from `error_message` (or `errorMessage`). `x-body-type: certlocker.core.exceptions.CLErrorException` is read from `error.message`. Any other body is used as the message.

```go
secret, err := service.GetSecret(ctx, id)
if err != nil {
    var te *trustclient.Error
    if errors.As(err, &te) && te.HasTrustError() {
        fmt.Printf("trust HTTP %d: %s\n", te.HTTPStatus, te.Message)
        return
    }
    fmt.Println(err)
    return
}
```

That snippet uses `errors` and `fmt`.

Builder validation (`url is required`, `apiToken must not be blank`, a non-HTTP URL, and the same class of mistakes) returns a plain `error`. OIDC exchange failures are `*trustclient.Error` as well, often with `HTTPStatus` left at 0 because the message already includes the HTTP status.

A step-up response is retried once. The second failure is returned to the caller.

## HTTP client

Default connect timeout is 10 seconds (`DefaultConnectTimeout`). Redirects are not followed (`RedirectNever`). HTTP/2 is used when the server offers it. The overall request timeout is unset; put a deadline on the context, or set `RequestTimeout`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

client, err := trustclient.NewBuilder().
    URL("https://trust.certlocker.io").
    AccountID("<accountId>").
    APIToken("<token>").
    ConnectTimeout(10 * time.Second).
    RequestTimeout(30 * time.Second).
    FollowRedirects(trustclient.RedirectNormal).
    Version(trustclient.HTTP1).
    NoProxy().
    Build(ctx)
```

| Builder method | Effect |
| --- | --- |
| `ConnectTimeout` | TCP dial timeout. Must be greater than 0. Default 10s |
| `RequestTimeout` | `http.Client.Timeout` for asset calls. `0` means no overall timeout |
| `FollowRedirects` | `RedirectNever` (default), `RedirectNormal` (blocks HTTPS → HTTP), `RedirectAlways` |
| `Version` | `HTTPVersionDefault`, `HTTP1`, or `HTTP2` |
| `Proxy` | Absolute proxy URL |
| `NoProxy` | Ignore environment proxy settings |
| `TLSConfig` | `*tls.Config` for the transport |
| `CookieJar` | `http.CookieJar` |
| `LocalAddr` | Local address to bind. Nil means any |
| `HTTPClient` | Use this `*http.Client` as given. Transport settings above are skipped. `Close` does not close it |

OIDC provider and exchange calls use their own short-lived client (10s connect, 30s request cap, 10s for GCP and Azure identity calls). They do not follow redirects.

## Development

```bash
go test ./...
```

## License

Licensed under GNU General Public License v3.0. See [LICENSE](LICENSE).
