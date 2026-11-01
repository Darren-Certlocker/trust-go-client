// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

// Package trustclient is the Go client for Certlocker Trust.
//
// It reads secrets, certificates, and tokens from the Trust Gateway, and it
// can authenticate with a UI-minted API token or by exchanging an OIDC id
// token (GitHub Actions, GCP, Azure, Azure DevOps, or an enrolled device).
//
// get methods return the asset record. fetch methods return the asset contents.
// Gateway paths include the tenant account id and that account must match the
// token's account.
package trustclient
