// (c) Dmitriy Blokhin [sv.dblokhin@gmail.com]. All rights reserved.
// License can be found in the LICENSE file.

package providers

import (
	"google.golang.org/api/oauth2/v2"
	"time"
	"errors"
	"net/http"
)

var (
	// GoogleProvider provides google pub jwk keys
	GoogleProvider google

	// valid iss values for google provider
	googleIss = []string{"accounts.google.com", "https://accounts.google.com"}

	// cached keys
	googleCache *oauth2.Jwk

	// errors
	errUnsupportedAlgorithm = errors.New("get key: cannot match pubkey by kid")
)

type google struct{}

// Iss provides valid iss list
func (g google) Iss() []string {
	return googleIss
}

// GetKeys provides google public jwk keys
func (g google) GetKeys() (*oauth2.Jwk, error) {
	var err error
	googleCache, err = getGoogleKeys(googleCache)

	return googleCache, err
}

// GetKey provides google public jwk key by kid
func (g google) GetKey(kid string) (*oauth2.JwkKeys, error) {
	var err error
	googleCache, err = getGoogleKeys(googleCache)
	if err != nil {
		return nil, err
	}

	for _, val := range googleCache.Keys {
		if val.Kid == kid {
			return val, nil
		}
	}

	return nil, errUnsupportedAlgorithm
}

func getGoogleKeys(cachedKeys *oauth2.Jwk) (*oauth2.Jwk, error) {
	if cachedKeys == nil {
		return loadGoogleKeys()
	} else {
		// check expired cachedKeys
		expires, err := time.Parse(time.RFC1123, cachedKeys.Header.Get("expires"))
		if err != nil {
			return nil, err
		}

		if expires.Before(time.Now()) {
			// return updated keys
			return loadGoogleKeys()
		}

		return cachedKeys, nil
	}
}

func loadGoogleKeys() (*oauth2.Jwk, error) {
	client, err := oauth2.New(http.DefaultClient)
	if err != nil {
		return nil, err
	}

	return client.GetCertForOpenIdConnect().Do()
}