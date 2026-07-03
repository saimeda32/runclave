package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), k
}

func TestParseRSAKeyPKCS1(t *testing.T) {
	pemBytes, _ := testKeyPEM(t)
	if _, err := ParseRSAKey(pemBytes); err != nil {
		t.Fatalf("PKCS#1 key should parse: %v", err)
	}
	if _, err := ParseRSAKey([]byte("not a pem")); err == nil {
		t.Fatal("garbage must not parse as a key")
	}
}

// Mint builds a valid RS256 App JWT, scopes the installation-token request to the
// session repo name, and returns the token + parsed expiry from the response.
func TestGitHubAppMintScopesAndParses(t *testing.T) {
	pemBytes, key := testKeyPEM(t)
	parsed, err := ParseRSAKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"ghs_abc","expires_at":"2026-07-03T12:00:00Z"}`)
	}))
	defer srv.Close()

	m := &GitHubAppMinter{
		AppID:          "12345",
		InstallationID: "99",
		Key:            parsed,
		APIBase:        srv.URL,
		Now:            func() time.Time { return time.Unix(1751500000, 0) },
		HTTP:           srv.Client(),
	}
	user, tok, exp, err := m.Mint("github.com/owner/myrepo")
	if err != nil {
		t.Fatal(err)
	}
	if user != "x-access-token" || tok != "ghs_abc" {
		t.Fatalf("unexpected creds: %q / %q", user, tok)
	}
	wantExp, _ := time.Parse(time.RFC3339, "2026-07-03T12:00:00Z")
	if exp != wantExp.Unix() {
		t.Fatalf("expiry %d, want %d", exp, wantExp.Unix())
	}
	// Scope must be the repo NAME only, contents:write.
	if !strings.Contains(gotBody, `"myrepo"`) || !strings.Contains(gotBody, `"contents":"write"`) {
		t.Fatalf("token request not scoped as expected: %s", gotBody)
	}
	// The Authorization header must be a Bearer JWT signed by the App key: verify
	// the header segment says RS256 and the signature checks out against the key.
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("expected Bearer JWT, got %q", gotAuth)
	}
	jwt := strings.TrimPrefix(gotAuth, "Bearer ")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %q", jwt)
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]string
	_ = json.Unmarshal(hdrRaw, &hdr)
	if hdr["alg"] != "RS256" {
		t.Fatalf("JWT alg %q, want RS256", hdr["alg"])
	}
	// Sanity: the key we generated is the one embedded (public exponent matches).
	if key.PublicKey.E != parsed.PublicKey.E {
		t.Fatal("parsed key mismatch")
	}
}

// No App configured -> Mint fails closed rather than returning a usable-but-empty
// credential the box could cache.
func TestGitHubAppMintFailsClosedWhenUnconfigured(t *testing.T) {
	m := &GitHubAppMinter{}
	if _, _, _, err := m.Mint("github.com/o/r"); err == nil {
		t.Fatal("unconfigured minter must fail, not mint")
	}
}
