package m2m

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestValidateClientID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "simple", id: "event-registration", wantErr: false},
		{name: "single char", id: "a", wantErr: false},
		{name: "max length", id: strings.Repeat("a", 64), wantErr: false},
		{name: "empty", id: "", wantErr: true},
		{name: "too long", id: strings.Repeat("a", 65), wantErr: true},
		{name: "uppercase", id: "Event-Registration", wantErr: true},
		{name: "underscore", id: "event_registration", wantErr: true},
		{name: "space", id: "event registration", wantErr: true},
		{name: "slash", id: "event/registration", wantErr: true},
		{name: "colon", id: "event:registration", wantErr: true},
		{name: "dot", id: "event.registration", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientID(tt.id)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateClientID(%q): expected error, got nil", tt.id)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateClientID(%q): %v", tt.id, err)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidClientID) {
				t.Fatalf("ValidateClientID(%q): error %v is not ErrInvalidClientID", tt.id, err)
			}
		})
	}
}

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name    string
		aud     string
		wantErr bool
	}{
		{name: "profiles", aud: "profiles-api", wantErr: false},
		{name: "hyphenated callee", aud: "event-registration-api", wantErr: false},
		{name: "global shape passes regex (per-callee choice is caller's)", aud: "icaa-api", wantErr: false},
		{name: "empty", aud: "", wantErr: true},
		{name: "missing suffix", aud: "profiles", wantErr: true},
		{name: "wrong suffix", aud: "profiles-apis", wantErr: true},
		{name: "uppercase", aud: "Profiles-api", wantErr: true},
		{name: "slash", aud: "profiles/api", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAudience(tt.aud)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateAudience(%q): expected error, got nil", tt.aud)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateAudience(%q): %v", tt.aud, err)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidAudience) {
				t.Fatalf("ValidateAudience(%q): error %v is not ErrInvalidAudience", tt.aud, err)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		{name: "single", scopes: []string{"m2m:player-profiles"}, wantErr: false},
		{name: "multiple", scopes: []string{"m2m:a", "m2m:b-c"}, wantErr: false},
		{name: "nil (scopeless identity)", scopes: nil, wantErr: false},
		{name: "empty (scopeless identity)", scopes: []string{}, wantErr: false},
		{name: "missing prefix", scopes: []string{"player-profiles"}, wantErr: true},
		{name: "empty scope value", scopes: []string{"m2m:"}, wantErr: true},
		{name: "uppercase", scopes: []string{"m2m:Player-Profiles"}, wantErr: true},
		{name: "one bad among good", scopes: []string{"m2m:a", "nope"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopes(tt.scopes)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateScopes(%v): expected error, got nil", tt.scopes)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateScopes(%v): %v", tt.scopes, err)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidScopes) {
				t.Fatalf("ValidateScopes(%v): error %v is not ErrInvalidScopes", tt.scopes, err)
			}
		})
	}
}

func TestValidateAudiences(t *testing.T) {
	tests := []struct {
		name      string
		audiences map[string][]string
		wantErr   bool
	}{
		{name: "single", audiences: map[string][]string{"profiles-api": {"m2m:player-profiles"}}, wantErr: false},
		{name: "multiple", audiences: map[string][]string{"a-api": {"m2m:x"}, "b-api": {}}, wantErr: false},
		{name: "nil", audiences: nil, wantErr: false},
		{name: "empty", audiences: map[string][]string{}, wantErr: false},
		{name: "bad key", audiences: map[string][]string{"profiles": {"m2m:x"}}, wantErr: true},
		{name: "bad scope entry", audiences: map[string][]string{"profiles-api": {"nope"}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAudiences(tt.audiences)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateAudiences(%v): expected error, got nil", tt.audiences)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateAudiences(%v): %v", tt.audiences, err)
			}
		})
	}
}

func TestGenerateClientSecret(t *testing.T) {
	seen := map[string]bool{}
	for range 10 {
		secret, err := GenerateClientSecret()
		if err != nil {
			t.Fatalf("GenerateClientSecret: %v", err)
		}
		if seen[secret] {
			t.Fatal("GenerateClientSecret returned a duplicate secret")
		}
		seen[secret] = true

		raw, err := base64.RawURLEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("secret %q is not base64url: %v", secret, err)
		}
		if len(raw) != ClientSecretBytes {
			t.Fatalf("secret decodes to %d bytes, want %d", len(raw), ClientSecretBytes)
		}
		if strings.Contains(secret, ":") {
			t.Fatalf("secret %q contains ':' (Basic-auth unsafe)", secret)
		}
	}
}
