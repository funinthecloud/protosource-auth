package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/funinthecloud/protosource-auth/keys"
)

// The federated-login state cookie is a short-lived, signed JWT minted with
// OUR default SELF issuer's signing key (EdDSA via keys.Resolver). It is the
// only thing that survives the round-trip out to the external IdP and back to
// /oauth/callback, so it carries everything the callback needs to finish the
// PKCE exchange without any server-side session store:
//
//   - verifier:     the PKCE code_verifier (replayed on the token exchange)
//   - redirect_uri: where to send the browser after a successful login
//   - state:        a random nonce echoed to the IdP and matched on return
//                   (CSRF / mix-up defence)
//   - idp:          the chosen EXTERNAL issuer_id (so the callback reloads the
//                   right Issuer + OIDCConfig)
//
// Signing (not just MAC) lets the callback verify the cookie with the
// resolver's VerificationKey(kid) by reading the kid from the JWT header,
// exactly like /authz/check verifies a shadow JWT. Tamper or expiry fails
// closed. The cookie is HttpOnly+Secure, so the verifier never reaches JS and
// only travels over TLS.
//
// NOTE: the payload is signed, not encrypted — a holder of the cookie can
// base64-decode the verifier. That is acceptable: PKCE protects the *code* in
// transit at the IdP redirect, and the cookie never leaves the legitimate
// browser. Do not log it.

// stateClaims is the JSON payload of the state cookie JWT.
type stateClaims struct {
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	IDP         string `json:"idp"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

// errStateInvalid is the single fail-closed sentinel for every state-cookie
// rejection (missing, malformed, bad signature, expired, wrong-state). The
// callback maps it uniformly to a 400 so it never leaks which check failed.
var errStateInvalid = errors.New("service: invalid or expired state")

// signState mints a signed state cookie JWT for the given payload, valid for
// ttl from now. It signs with the default SELF issuer's current key for
// algorithm (the same key the shadow JWT is signed with), so VerificationKey
// can resolve it on the callback by kid.
func signState(
	ctx context.Context,
	resolver *keys.Resolver,
	selfIssuerID, algorithm string,
	verifier, redirectURI, state, idp string,
	now time.Time,
	ttl time.Duration,
) (string, error) {
	claims := stateClaims{
		Verifier:    verifier,
		RedirectURI: redirectURI,
		State:       state,
		IDP:         idp,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("service: marshal state: %w", err)
	}
	lk, err := resolver.SigningKey(ctx, selfIssuerID, algorithm)
	if err != nil {
		return "", fmt.Errorf("service: state signing key: %w", err)
	}
	jwt, err := lk.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("service: sign state: %w", err)
	}
	return jwt, nil
}

// verifyState validates a state cookie JWT and returns its claims. It reads
// the kid from the JWT header, fetches the matching verification key, checks
// the signature, the expiry against now, and that the embedded state nonce
// matches expectState (the value echoed back by the IdP). Any failure returns
// errStateInvalid — fail closed, no detail leaked.
func verifyState(
	ctx context.Context,
	resolver *keys.Resolver,
	jwt, expectState string,
	now time.Time,
) (*stateClaims, error) {
	if jwt == "" || expectState == "" {
		return nil, errStateInvalid
	}
	kid, err := jwtHeaderKid(jwt)
	if err != nil {
		return nil, errStateInvalid
	}
	lk, err := resolver.VerificationKey(ctx, kid)
	if err != nil {
		return nil, errStateInvalid
	}
	payload, err := lk.Verify(jwt)
	if err != nil {
		return nil, errStateInvalid
	}
	var claims stateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errStateInvalid
	}
	if claims.ExpiresAt == 0 || now.Unix() >= claims.ExpiresAt {
		return nil, errStateInvalid
	}
	// Constant-ish equality is unnecessary here (the nonce is not a secret
	// MAC), but a mismatch must fail closed.
	if claims.State == "" || claims.State != expectState {
		return nil, errStateInvalid
	}
	return &claims, nil
}

// jwtHeaderKid extracts the "kid" from the header segment of a compact JWS.
// It does not verify the signature — that is verifyState's job once the key
// is resolved.
func jwtHeaderKid(jwt string) (string, error) {
	first, _, ok := strings.Cut(jwt, ".")
	if !ok || first == "" {
		return "", errStateInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return "", errStateInvalid
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil || hdr.Kid == "" {
		return "", errStateInvalid
	}
	return hdr.Kid, nil
}
