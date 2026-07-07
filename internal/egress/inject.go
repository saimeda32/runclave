package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
)

// mitmInject terminates the box's TLS to `hostport` with a CA-minted cert, then
// forwards each request to the real host over a fresh TLS connection, FORCING the
// credential header (rule) onto it. The real secret is only ever set here, in the
// gateway; the box's request carries at most a placeholder, which is overwritten.
//
// The MITM leaf advertises only http/1.1 (ALPN), so the box speaks HTTP/1.1 to the
// gateway while the gateway speaks whatever the real host negotiates (often h2) - a
// simpler, robust split than terminating h2. Hosts that need h2/websockets end to
// end are simply left out of the inject list and blind-tunnelled instead.
func (p *Proxy) mitmInject(srcConn net.Conn, hostport, hostname string, rule InjectRule) {
	defer srcConn.Close()
	leaf, err := p.ca.LeafFor(hostname)
	if err != nil {
		return
	}
	tlsConn := tls.Server(srcConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
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
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed or malformed - done with this connection
		}
		// Rebuild the request as an outbound one to the REAL host, and force the
		// credential header (Set overwrites any placeholder the box sent).
		req.URL.Scheme = "https"
		req.URL.Host = hostport
		req.Host = hostname
		req.RequestURI = "" // required: RoundTrip rejects a set RequestURI
		req.Header.Set(rule.Header, rule.Value)

		resp, err := transport.RoundTrip(req)
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
