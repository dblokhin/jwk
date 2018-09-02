// (c) Dmitriy Blokhin [sv.dblokhin@gmail.com]. All rights reserved.
// License can be found in the LICENSE file.

package jwk

import (
	"errors"
	"crypto/rsa"
	"google.golang.org/api/oauth2/v2"
	"time"
	"strings"
	"encoding/base64"
	"encoding/json"
	"crypto/sha256"
	"crypto"
	"crypto/sha512"
)

/*
 RFC doc: https://tools.ietf.org/html/rfc7517
*/

var (
	errInvalidAudience      = errors.New("verify: invalid token audience")
	errInvalidIss           = errors.New("verify: invalid token issuer")
	errInvalidExpireTime    = errors.New("verify: token is expired")
	errNoTokenID            = errors.New("verify: the verify method requires an ID Token")
	errInvalidToken         = errors.New("verify: invalid token received, token must have 3 parts")
	errInvalidTokenEnvelope = errors.New("verify: can't parse token envelope")
	errInvalidTokenPayload  = errors.New("verify: can't parse token payload")
	errUnsupportedAlgorithm = errors.New("verify: cannot verify signature: algorithm unimplemented")
)

var pubKeysCache *oauth2.Jwk

// New parses oauth id_token
func New(tokenID string, Issuer []string) (*TokenID, error) {
	var err error

	if len(tokenID) == 0 {
		return nil, errNoTokenID
	}

	parts := strings.Split(tokenID, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	tok := new(TokenID)
	tok.issuer = Issuer
	tok.signedContent = parts[0] + "." + parts[1]
	tok.signatureString, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	header := json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(parts[0])))
	if err = header.Decode(&tok.header); err != nil {
		return nil, errInvalidTokenEnvelope
	}

	payload := json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(parts[1])))
	if err = payload.Decode(&tok.info); err != nil {
		return nil, errInvalidTokenPayload
	}

	/*tt, err := base64.RawURLEncoding.DecodeString(parts[0])
	log.Println(string(tt), err)

	tt, err = base64.RawURLEncoding.DecodeString(parts[1])
	log.Println(string(tt), err)

	log.Printf("%#v\n", tok.header)
	log.Printf("%#v\n", tok.info)*/

	return tok, nil
}

type envelope struct {
	Alg string `json:"alg"`
	Kid string `json:"Kid"`
	// Kty string `json:"kty"`
	// Use string `json:"use"`
	// N   string `json:"n"`
	// E   string `json:"e"`
}

// TokenID is oauth id token
type tokenInfo struct {
	Iss     string `json:"iss"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Aud     string `json:"aud"`
	//AuthTime       int64  `json:"auth_time"`
	//UserID         string `json:"user_id"`
	Sub            string `json:"sub"`
	Iat            int64  `json:"iat"`
	Exp            int64  `json:"exp"`
	Email          string `json:"email"`
	EmailVerified  bool   `json:"email_verified"`
	SignInProvider string `json:"sign_in_provider"`
}

type TokenID struct {
	header          envelope
	info            tokenInfo
	signedContent   string
	signatureString []byte

	issuer []string
}

func (t *TokenID) checkExpiryTime() bool {
	// The expiry time (exp) of the ID token has not passed.
	return time.Unix(t.info.Exp, 0).After(time.Now())
}

// Verify verifies oauth id token
func (t *TokenID) Verify(provider KeyProvider, audience string) error {
	var err error

	// Google dev docs:
	// https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token

	// 1. Check the audience
	if t.info.Aud != audience {
		return errInvalidAudience
	}

	// 2. Check the issuer
	validIssuer := false
	for _, issuer := range t.issuer {
		validIssuer = t.info.Iss == issuer
		if validIssuer {
			break
		}
	}

	if !validIssuer {
		return errInvalidIss
	}

	// 3. Check the expiry time
	if !t.checkExpiryTime() {
		return errInvalidExpireTime
	}

	// 4. Check the sig
	// 		a. upload google pubkeys
	// 		b. choose the pubkey by Kid field (in token.header)
	// 		c. verify

	key, err := provider.GetKey(t.header.Kid)
	if err != nil {
		return err
	}

	switch key.Kty {
	case "RSA": return t.verifyRSA(key)

	default:
		return errUnsupportedAlgorithm
	}
}

func (t *TokenID) verifyRSA(key *oauth2.JwkKeys) error {

	rsaPub, err := jwkToRSA(key)
	if err != nil {
		return err
	}

	// verify sig
	switch key.Alg {
	case "RS256":
		h := sha256.New()
		h.Write([]byte(t.signedContent))
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h.Sum(nil), t.signatureString)

	case "RS384":
		h := sha512.New384()
		h.Write([]byte(t.signedContent))
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA3_384, h.Sum(nil), t.signatureString)

	case "RS512":
		h := sha512.New()
		h.Write([]byte(t.signedContent))
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, h.Sum(nil), t.signatureString)

	default:
		return errUnsupportedAlgorithm
	}
}

// Name returns user token Name
func (t *TokenID) Name() string {
	return t.info.Name
}

// Email returns user token Email
func (t *TokenID) Email() string {
	return t.info.Email
}

// EmailVerified returns user token EmailVerified
func (t *TokenID) EmailVerified() bool {
	return t.info.EmailVerified
}

// Picture returns user token Picture
func (t *TokenID) Picture() string {
	return t.info.Picture
}

// Audience returns user token Audience
func (t *TokenID) Audience() string {
	return t.info.Aud
}
