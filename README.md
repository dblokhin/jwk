# Works OAuth id tokens on Golang
Package provides easy and secure offline method to OAuth verify `id_token`.

## Lisense 
MIT License

## Problem
The `https://github.com/google/google-api-go-client` package doesn't provide the offline `verify()` for OAuth `id_token`, which is priority method than call api [https://www.googleapis.com/oauth2/v2/tokeninfo](https://www.googleapis.com/oauth2/v2/tokeninfo).
You can use online checking `id_token`, but it's significant slower:

```golang
func verifyIdToken(idToken string) (*oauth2.Tokeninfo, error) {
    srv, err := oauth2.New(httpClient)
    return srv.Tokeninfo().IdToken(idToken).Do()
}
```

Also https://godoc.org/golang.org/x/oauth2/jws#Verify should be able to verify tokens, but this package was marked as deprecated:
> Deprecated: this package is not intended for public use and might be removed in the future. It exists for internal use only. Please switch to another JWS package or copy this package into your own source tree.

## Golang offline verify the integrity of the OAuth id token
Google dev docs, how to: https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token

```golang
import (
	...
	"github.com/dblokhin/jwk"
	"github.com/dblokhin/jwk/providers"
)

...

        // EXAMPLE 
	tokenID := "id_token_string"

	// parse token from string
	token, err := jwk.New(tokenID, providers.GoogleProvider.Iss())
	if err != nil {
		return err
	}
	
	// verify token with Google keys provider
	err = token.Verify(providers.GoogleProvider, "your-audience")
	if err != nil {
		return err
	}
	
	// access to token fields
	userName := token.Name()
	userPhoto := token.Picture()
```

`providers.GoogleProvider` automatically caches & manages Google JWK public keys. See code inside for detail.

## Another key providers
You can create your own key providers by implementing `KeyProvider` interface:
```golang
// KeyProvider provides public certs
type KeyProvider interface {
	// GetKeys provides keys
	GetKeys() (*oauth2.Jwk, error)

	// GetKey provides key by kid
	GetKey(kid string) (*oauth2.JwkKeys, error)
}
```


## Contributing
You are welcome! Github issues is the best place for that's purposes.