package broker

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubAppMinter mints short-lived GitHub App installation tokens. The App
// private key stays here on the host and is never copied into the box; the box
// only ever receives a ~1h token scoped to the session repo with the App's
// permissions. This is the production TokenMinter behind the broker.
//
// It is configured, not hardcoded: an operator supplies the App ID, the
// installation ID for the owner, and the RSA private key. With none configured,
// the daemon simply has no minter and the broker fails closed (no git creds in
// the box) rather than falling back to a long-lived secret.
type GitHubAppMinter struct {
	AppID          string
	InstallationID string
	Key            *rsa.PrivateKey
	// APIBase defaults to https://api.github.com; overridable for tests. The
	// daemon reaches this from the HOST, outside the box's egress boundary.
	APIBase string
	// Now is injected so tests are deterministic; nil means time.Now.
	Now func() time.Time
	// HTTP is injected for tests; nil means http.DefaultClient.
	HTTP *http.Client
}

// ParseRSAKey loads a PEM-encoded RSA private key (PKCS#1 or PKCS#8), the format
// GitHub hands out for an App. Returned so the daemon can read the key once at
// startup and keep only the parsed key in memory.
func ParseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("broker: no PEM block in private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("broker: private key is neither PKCS#1 nor PKCS#8: %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("broker: private key is not RSA")
	}
	return rk, nil
}

func (m *GitHubAppMinter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// appJWT builds the short-lived (<=10m) RS256 JWT that authenticates as the App.
func (m *GitHubAppMinter) appJWT() (string, error) {
	if m.Key == nil || m.AppID == "" {
		return "", fmt.Errorf("broker: GitHub App not configured (need app id + key)")
	}
	now := m.now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	// iat backdated 60s to tolerate host/GitHub clock skew; exp well under the 10m cap.
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": m.AppID,
	}
	seg := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	h, err := seg(header)
	if err != nil {
		return "", err
	}
	c, err := seg(claims)
	if err != nil {
		return "", err
	}
	signingInput := h + "." + c
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// repoName extracts the "name" from a "host/owner/name" session repo. The
// installation-token request scopes to the repo name; the installation already
// binds the owner.
func repoName(repo string) string {
	parts := strings.Split(strings.TrimSuffix(repo, ".git"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// Mint requests an installation token scoped to exactly the session repo, with
// contents:write (enough to push). Returns x-access-token / the token / its
// expiry, matching the TokenMinter contract.
func (m *GitHubAppMinter) Mint(repo string) (string, string, int64, error) {
	jwt, err := m.appJWT()
	if err != nil {
		return "", "", 0, err
	}
	if m.InstallationID == "" {
		return "", "", 0, fmt.Errorf("broker: no installation id configured")
	}
	name := repoName(repo)
	if name == "" {
		return "", "", 0, fmt.Errorf("broker: cannot derive repo name from %q", repo)
	}
	base := m.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	body, _ := json.Marshal(map[string]any{
		"repositories": []string{name},
		"permissions":  map[string]string{"contents": "write"},
	})
	url := base + "/app/installations/" + m.InstallationID + "/access_tokens"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	cl := m.HTTP
	if cl == nil {
		cl = http.DefaultClient
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", "", 0, fmt.Errorf("broker: installation token request failed: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", 0, fmt.Errorf("broker: bad token response: %w", err)
	}
	if out.Token == "" {
		return "", "", 0, fmt.Errorf("broker: token response had no token")
	}
	exp, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return "", "", 0, fmt.Errorf("broker: bad expiry %q: %w", out.ExpiresAt, err)
	}
	return "x-access-token", out.Token, exp.Unix(), nil
}
