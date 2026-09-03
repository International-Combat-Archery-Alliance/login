package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"slices"

	"github.com/International-Combat-Archery-Alliance/login/api"
)

// staticJWKSProvider serves a fixed key set derived once at startup from the
// configured signing keys.
type staticJWKSProvider struct {
	jwks api.JWKS
}

func (s staticJWKSProvider) PublicJWKS(context.Context) (api.JWKS, error) {
	return s.jwks, nil
}

// keypairJWKS builds a JWKS from the machine + user private-key sets.
func keypairJWKS(machineKeys map[string]*rsa.PrivateKey, userKeys map[string]*rsa.PrivateKey) api.JWKS {
	jwks := api.JWKS{Keys: []api.JWK{}}
	for _, kid := range sortedKids(machineKeys) {
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(kid, machineKeys[kid]))
	}
	for _, kid := range sortedKids(userKeys) {
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(kid, userKeys[kid]))
	}
	return jwks
}

func sortedKids[K any](m map[string]K) []string {
	kids := make([]string, 0, len(m))
	for kid := range m {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	return kids
}

// rsaPublicJWK converts an RSA private key's public half into JWK shape.
func rsaPublicJWK(kid string, priv *rsa.PrivateKey) api.JWK {
	use := "sig"
	alg := "RS256"
	kty := "RSA"
	return api.JWK{
		Kty: api.JWKKty(kty),
		Kid: kid,
		Use: (*api.JWKUse)(&use),
		Alg: (*api.JWKAlg)(&alg),
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
}