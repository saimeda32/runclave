package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// injectIdleTimeout bounds how long the MITM connection may sit idle (handshake, or
// waiting for the next request) before it is dropped - so a box that opens a
// connection and sends nothing can't pin a goroutine + a completed TLS handshake.
const injectIdleTimeout = 60 * time.Second

// hopByHop headers are connection-scoped and must not be forwarded upstream.
var hopByHop = []string{"Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Connection", "Upgrade"}

// mitmInject terminates the box's TLS to `hostport` with a CA-minted cert, then
// forwards each request to the real host over a fresh TLS connection, FORCING the
// credential header (rule) onto it. The box's request carries at most a placeholder,
// which is OVERWRITTEN before the request reaches the upstream.
//
// What this guarantees, precisely: the raw secret VALUE never enters the box. What
// it does NOT do: the box still gets full authenticated USE of the host (unlimited
// calls - this is not rate limiting), and it reads the whole response, so if an
// injected host reflects request headers back (an echo/debug endpoint), the box
// could read the credential out. Only inject hosts known not to reflect credentials.
//
// The MITM leaf advertises only http/1.1 (ALPN), so the box speaks HTTP/1.1 to the
// gateway while the gateway speaks whatever the real host negotiates (often h2) - a
// simpler split than terminating h2. Hosts needing h2/websockets end to end are left
// out of the inject list and blind-tunnelled instead.
func (p *Proxy) mitmInject(srcConn net.Conn, hostport, hostname string, rule InjectRule) {
	defer srcConn.Close()
	if p.injectSem != nil {
		defer func() { <-p.injectSem }()
	}
	leaf, err := p.ca.LeafFor(hostname)
	if err != nil {
		return
	}
	tlsConn := tls.Server(srcConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(injectIdleTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	transport := p.injectTransport
	if transport == nil {
		transport = http.DefaultTransport
	}

	br := bufio.NewReader(tlsConn)
	for {
		// Bound idle-waiting for the next request (the send-nothing DoS); clear it
		// once a request is in flight so a legit slow upload/stream isn't killed.
		_ = tlsConn.SetReadDeadline(time.Now().Add(injectIdleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = tlsConn.SetReadDeadline(time.Time{})

		// Answer Expect: 100-continue so a strict client sends its body.
		if req.Header.Get("Expect") == "100-continue" {
			_, _ = io.WriteString(tlsConn, "HTTP/1.1 100 Continue\r\n\r\n")
			req.Header.Del("Expect")
		}
		// Rebuild as an outbound request to the REAL host and force the credential.
		req.URL.Scheme = "https"
		req.URL.Host = hostport
		req.Host = hostname
		req.RequestURI = ""
		for _, h := range hopByHop {
			req.Header.Del(h)
		}
		req.Header.Set(rule.Header, rule.Value) // Set overwrites any placeholder

		resp, err := transport.RoundTrip(req)
		// Drain any unsent request body so leftover bytes can't desync the next
		// keep-alive request on this connection.
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		if err != nil {
			// Never surface the token in an error; a bare 502 is enough.
			_, _ = io.WriteString(tlsConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		werr := resp.Write(tlsConn)
		_ = resp.Body.Close()
		if werr != nil || req.Close || resp.Close {
			return
		}
	}
}
