package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"slices"

	"github.com/International-Combat-Archery-Alliance/login/api"
)

// staticJWKSProvider serves a fixed key set. The JWKS is derived once at
// startup from the signing keys fetchAppConfig already loaded from SSM — the
// same material the signer uses — so serving cannot fail, go stale, or drift
// from what login actually signs with. Key rotation is an SSM edit + redeploy
// (cold starts serve the new set; verifiers lazy-refetch on an unknown kid).
type staticJWKSProvider struct {
	jwks api.JWKS
}

func (s staticJWKSProvider) PublicJWKS(context.Context) (api.JWKS, error) {
	return s.jwks, nil
}

// keypairJWKS builds a JWKS from a private-key set.
func keypairJWKS(keys map[string]*rsa.PrivateKey) api.JWKS {
	jwks := api.JWKS{Keys: []api.JWK{}}
	for _, kid := range sortedKids(keys) {
		jwks.Keys = append(jwks.Keys, rsaPublicJWK(kid, keys[kid]))
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

// rsaPublicJWK converts an RSA private key's public half into the JWK shape
// served by the JWKS endpoint (JWKS-only key distribution — there is no
// /jwtPublicKeys SSM mirror).
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