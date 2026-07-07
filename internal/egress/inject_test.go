package egress

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tlsEcho is a TLS upstream that reports back the Authorization header it received.
type tlsEcho struct {
	srv      *httptest.Server
	hostport string
}

func newTLSEchoServer(t *testing.T) *tlsEcho {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	return &tlsEcho{srv: srv, hostport: strings.TrimPrefix(srv.URL, "https://")}
}

func (e *tlsEcho) Close()                             { e.srv.Close() }
func (e *tlsEcho) clientTransport() http.RoundTripper { return e.srv.Client().Transport }
func (e *tlsEcho) clientTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(e.srv.Certificate())
	return &tls.Config{RootCAs: pool}
}

// The whole point of injection: the box sends a PLACEHOLDER credential; the gateway
// replaces it with the real secret before the request reaches the upstream, so the
// real secret is never in the box. This drives it end to end with a real TLS
// handshake (box trusts the CA, MITM, forward to a real upstream).
func TestCredentialInjectionReplacesPlaceholder(t *testing.T) {
	// Upstream that reports back the Authorization header it actually received.
	upstream := newTLSEchoServer(t)
	defer upstream.Close()
	upHost := upstream.hostport // 127.0.0.1:PORT
	hostname, _, _ := net.SplitHostPort(upHost)

	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	proxy := New([]string{hostname}, nil) // allow the upstream host
	proxy.injectTransport = upstream.clientTransport()
	if err := proxy.SetInjector(ca, map[string]InjectRule{
		hostname: {Header: "Authorization", Value: "Bearer REAL-SECRET"},
	}); err != nil {
		t.Fatal(err)
	}

	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	go http.Serve(pl, proxy)

	// A "box" client: routes through the proxy and trusts the gateway CA (for MITM).
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	proxyURL, _ := url.Parse("http://" + pl.Addr().String())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}

	req, _ := http.NewRequest("GET", "https://"+upHost+"/x", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER") // the box only has a placeholder
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through injecting proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, "auth=Bearer REAL-SECRET") {
		t.Fatalf("gateway must inject the real secret, upstream saw: %q", got)
	}
	if strings.Contains(got, "PLACEHOLDER") {
		t.Fatalf("the placeholder must NOT reach the upstream: %q", got)
	}
}

// A POST with a body, reused over keep-alive, must inject on EVERY request and not
// desync (the second request must parse correctly and also get the real secret).
func TestInjectPostBodyAndKeepAlive(t *testing.T) {
	// Upstream echoes the auth header AND the body length it received.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "auth=%s len=%d", r.Header.Get("Authorization"), len(b))
	}))
	defer srv.Close()
	upHost := strings.TrimPrefix(srv.URL, "https://")
	hostname, _, _ := net.SplitHostPort(upHost)

	ca, _ := GenerateCA()
	proxy := New([]string{hostname}, nil)
	proxy.injectTransport = srv.Client().Transport
	_ = proxy.SetInjector(ca, map[string]InjectRule{hostname: {Header: "Authorization", Value: "Bearer REAL"}})

	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pl.Close()
	go http.Serve(pl, proxy)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	proxyURL, _ := url.Parse("http://" + pl.Addr().String())
	// One client/transport so keep-alive reuses the same MITM connection.
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", "https://"+upHost+"/x", strings.NewReader("hello-body"))
		req.Header.Set("Authorization", "Bearer PLACEHOLDER")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "auth=Bearer REAL") || !strings.Contains(string(body), "len=10") {
			t.Fatalf("request %d: injection/body wrong: %q", i, body)
		}
	}
}

// A host that is NOT injected is blind-tunnelled (no MITM), unchanged behaviour.
func TestNonInjectedHostIsTunnelled(t *testing.T) {
	upstream := newTLSEchoServer(t)
	defer upstream.Close()
	upHost := upstream.hostport
	hostname, _, _ := net.SplitHostPort(upHost)

	ca, _ := GenerateCA()
	proxy := New([]string{hostname}, nil)
	// injector configured but for a DIFFERENT host, so this host is tunnelled
	_ = proxy.SetInjector(ca, map[string]InjectRule{})

	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pl.Close()
	go http.Serve(pl, proxy)

	proxyURL, _ := url.Parse("http://" + pl.Addr().String())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: upstream.clientTLSConfig(), // trust the REAL upstream (no MITM here)
	}}
	req, _ := http.NewRequest("GET", "https://"+upHost+"/x", nil)
	req.Header.Set("Authorization", "Bearer MINE")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("tunnelled request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth=Bearer MINE") {
		t.Fatalf("a non-injected host must pass the box's own header through: %q", body)
	}
}

// The CA must refuse an inject host that isn't in the allowlist (injection is not a
// bypass).
func TestInjectRequiresAllowlisted(t *testing.T) {
	ca, _ := GenerateCA()
	proxy := New([]string{"api.anthropic.com"}, nil)
	if err := proxy.SetInjector(ca, map[string]InjectRule{"evil.example.com": {Header: "Authorization", Value: "x"}}); err == nil {
		t.Fatal("injecting a non-allowlisted host must be refused")
	}
}
