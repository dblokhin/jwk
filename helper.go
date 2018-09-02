// (c) Dmitriy Blokhin [sv.dblokhin@gmail.com]. All rights reserved.
// License can be found in the LICENSE file.

package jwk

import (
	"crypto/rsa"
	"google.golang.org/api/oauth2/v2"
	"math/big"
	"encoding/base64"
	"encoding/binary"
	"bytes"
	"errors"
)

var (
	errParseCertificate     = errors.New("verify: can't parse verification certificates")
)

func jwkToRSA(key *oauth2.JwkKeys) (*rsa.PublicKey, error) {
	// convert n
	n := new(big.Int)
	bytesN, err := base64.URLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, errParseCertificate
	}
	n.SetBytes(bytesN)

	// convert e
	var e uint32
	bytesE, err := base64.URLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, errParseCertificate
	}

	// alignment E bytes to 4
	for len(bytesE) % 4 != 0 {
		bytesE = append([]byte{0}, bytesE...)
	}

	if err := binary.Read(bytes.NewReader(bytesE), binary.BigEndian, &e); err != nil {
		return nil, errParseCertificate
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}
