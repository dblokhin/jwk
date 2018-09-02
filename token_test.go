// (c) Dmitriy Blokhin [sv.dblokhin@gmail.com]. All rights reserved.
// License can be found in the LICENSE file.

package jwk

import (
	"testing"
	"interfaces/jwk/providers"
)

func verify(tokenID, audience string, iss []string) error {
	tok, err := New(tokenID, iss)
	if err != nil {
		return err
	}

	return tok.Verify(providers.GoogleProvider, audience)
}

var (
	// gapi.client.getToken().id_token
	gapiTokenID = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjU1Yjg1NGVkZjM1ZjA5M2I0NzA4ZjcyZGVjNGYxNTE0OTgzNmU4YWMifQ.eyJhenAiOiIxNDk4NjExNjA2MzItNjc5ODk4dTllazFqcHBoZGkxcGFudTJmN2dic3FnMW4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNDk4NjExNjA2MzItNjc5ODk4dTllazFqcHBoZGkxcGFudTJmN2dic3FnMW4uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTU5MzYyMjQyNzgyMDMzNjkxMzciLCJlbWFpbCI6InN2LmRibG9raGluQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiWG9CckhkeFRaWTI2OWROdHJwU3VIdyIsImV4cCI6MTUzNTg2NjcyNCwiaXNzIjoiYWNjb3VudHMuZ29vZ2xlLmNvbSIsImp0aSI6ImI3MDZiMTY3NDcxNDI2N2MwNTNkNGM1NWQ0YjU1OGJhMjMwMjEyZDMiLCJpYXQiOjE1MzU4NjMxMjQsIm5hbWUiOiJEbWl0cml5IEJsb2toaW4iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1fQTlaTXBXX2tPMC9BQUFBQUFBQUFBSS9BQUFBQUFBQUFxcy9PVzFmYmxUNVl4OC9zOTYtYy9waG90by5qcGciLCJnaXZlbl9uYW1lIjoiRG1pdHJpeSIsImZhbWlseV9uYW1lIjoiQmxva2hpbiIsImxvY2FsZSI6InJ1In0.pGA6DNiCF8mR-bzSsZjPnNVuNTnKJXHcP4rVMv4-rqcjNnPWOirSK23CCLGfH3xMKWtdQMcMWgGdvEZSK7g_aL8SgJmzhRPgyGmpu3bKsl2elduB6jILqwLHFXEG0KiarKY3fhAfY12ac91B2YjXJDY8Wp8sSFq2Nfit2t2hJPanISQKRC5Fpmc4B9OiVDEUOR12ETTWCZoPF0s_uajTMHVa5wjvencNUgizMiY4kk1tGpav1P69yi0riIy60_iZZvpWyAYiDE0s6g9CSPDqKchpwXE0LAWzWkiFd6t7oCTqWOX2BVeSZB4WvcQ6s4Xb5_aGXxz3g2EIURegYRo9AA`

	// firebase.auth().currentUser.getIdToken().then(res => console.log(res))
	firebaseTokenID = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImEwY2ViNDY3NDJhNjNlMTk2NDIxNjNhNzI4NmRjZDQyZjc0MzYzNjYifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20va3MtYXBwLTYzMWFlIiwibmFtZSI6IkRtaXRyaXkgQmxva2hpbiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLV9BOVpNcFdfa08wL0FBQUFBQUFBQUFJL0FBQUFBQUFBQXFzL09XMWZibFQ1WXg4L3Bob3RvLmpwZyIsImF1ZCI6ImtzLWFwcC02MzFhZSIsImF1dGhfdGltZSI6MTUzNTY4OTk2NywidXNlcl9pZCI6ImFuZ3ZjMDExWEJNaHVmWGRscGpvTmpFRXF2azIiLCJzdWIiOiJhbmd2YzAxMVhCTWh1ZlhkbHBqb05qRUVxdmsyIiwiaWF0IjoxNTM1ODY1NzQ3LCJleHAiOjE1MzU4NjkzNDcsImVtYWlsIjoic3YuZGJsb2toaW5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMTU5MzYyMjQyNzgyMDMzNjkxMzciXSwiZW1haWwiOlsic3YuZGJsb2toaW5AZ21haWwuY29tIl19LCJzaWduX2luX3Byb3ZpZGVyIjoiZ29vZ2xlLmNvbSJ9fQ.IBQIns_iCe-qPE0OMDDVIb39SW57a9vbupjHpJb8EFoINjTdig9mIpetCow3H6SX0BleG4_eKatNMjPuW2kACRSQx6oD63byS6zq35hJPqB2OZ0tU4X3HSiwAayn9O15uObkgMwRZXU9nNyoBda97ox4fFjOlbIX-k_t3SG9uX-LEhLhOzO3m79AWRdEAMkzcnwt-DpCS_mHybXzQgg3w_mFtZ7KKC5Xf_2czmUFOmh6-lO384leAFQH57s_BQaOzA-8M5b5xfMgH6xJn2V5PiIwRPcgAcMM213IpHyMvVq0L6NJ6GALDHAUdS7-eXLdNBKfU5hhEWNlgUsGLJYt9A"
)

func TestTokenID_Verify(t *testing.T) {

	/*err := verify(gapiTokenID, "149861160632-679898u9ek1jpphdi1panu2f7gbsqg1n.apps.googleusercontent.com", providers.GoogleProvider.Iss())
	if err != nil {
		t.Error("verify google failed:", err)
	}*/

	err := verify(firebaseTokenID, "ks-app-631ae", []string{"https://securetoken.google.com/ks-app-631ae"})
	if err != nil {
		t.Error("verify firebase failed:", err)
	}
}

func TestNew(t *testing.T) {
	_, err := New("", nil)
	if err != errNoTokenID {
		t.Errorf("new() failed: got %v expected %v", err, errNoTokenID)
	}
}
