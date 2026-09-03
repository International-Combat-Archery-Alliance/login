package m2m

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

const (
	// ClientSecretBytes is the CSPRNG entropy per provisioned clientSecret.
	// Encoded base64url it fits the exchange's maxM2MSecretLen with room to
	// spare and never contains ':' (Basic-auth safe).
	ClientSecretBytes = 32
	// MaxSecretRounds caps secretRounds[]: the current round plus its
	// predecessor, so the previous secret keeps working until callers recycle
	// after a rotation.
	MaxSecretRounds = 2
)

// Canonical provisioning formats. Mirrored as `pattern`s in spec/api.yaml —
// keep both in sync.
var (
	clientIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	audiencePattern = regexp.MustCompile(`^[a-z0-9-]+-api$`)
	scopePattern    = regexp.MustCompile(`^m2m:[a-z0-9-]+$`)
)

// Sentinel validation verdicts (transport maps these to HTTP 400).
var (
	ErrInvalidClientID = errors.New("invalid clientId")
	ErrInvalidAudience = errors.New("invalid audience")
	ErrInvalidScopes   = errors.New("invalid scopes")
)

// ValidateClientID reports whether id matches ^[a-z0-9-]{1,64}$.
func ValidateClientID(id string) error {
	if !clientIDPattern.MatchString(id) {
		return fmt.Errorf("%w: must match ^[a-z0-9-]{1,64}$", ErrInvalidClientID)
	}
	return nil
}

// ValidateAudience reports whether aud matches <callee>-api (per-callee
// audience, never the global icaa-api).
func ValidateAudience(aud string) error {
	if !audiencePattern.MatchString(aud) {
		return fmt.Errorf("%w: must match <callee>-api", ErrInvalidAudience)
	}
	return nil
}

// ValidateScopes reports whether every entry matches m2m:<callee-scope>
// (exact scopes, never prefixes). Empty is allowed: a scopeless client
// authenticates but authorizes nowhere, since callees require an exact scope.
// This supports provisioning an identity before its scopes exist; note scopes
// cannot be granted later via this API (revoke + recreate instead).
func ValidateScopes(scopes []string) error {
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope) {
			return fmt.Errorf("%w: %q must match m2m:<callee-scope>", ErrInvalidScopes, scope)
		}
	}
	return nil
}

// GenerateClientSecret returns base64url(32 CSPRNG bytes) — 43 chars, shown
// to the admin exactly once and never persisted in plaintext outside SSM.
func GenerateClientSecret() (string, error) {
	raw := make([]byte, ClientSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random bytes for client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
