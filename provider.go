// (c) Dmitriy Blokhin [sv.dblokhin@gmail.com]. All rights reserved.
// License can be found in the LICENSE file.

package jwk

import (
	"google.golang.org/api/oauth2/v2"
)

// KeyProvider provides public certs
type KeyProvider interface {
	// GetKeys provides keys
	GetKeys() (*oauth2.Jwk, error)

	// GetKey provides key by kid
	GetKey(kid string) (*oauth2.JwkKeys, error)
}
