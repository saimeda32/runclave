package broker

import (
	"bufio"
	"io"
	"net"
	"strings"
	"time"
)

// A credential-helper request is a few hundred bytes; these bound a compromised
// box's ability to exhaust the host. maxReqBytes caps a single request, connTTL
// caps how long a connection may sit idle, and maxConns caps concurrency.
const (
	maxReqBytes = 64 << 10
	connTTL     = 5 * time.Second
	maxConns    = 64
)

// Serve accepts connections on l and answers each as one credential-helper call
// for this session. It blocks until l is closed (Accept returns an error). Each
// connection is one call: the client writes the op on the first line, then the
// git attribute lines, then half-closes; the server writes the response and
// closes. A malformed or unauthorized call yields an empty response, which git
// reads as "no credential" and falls back - the daemon never hands back a
// partial or guessed credential.
func Serve(l net.Listener, s *Session) error {
	sem := make(chan struct{}, maxConns)
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		sem <- struct{}{} // bound concurrent (and thus total live) goroutines
		go func() {
			defer func() { <-sem }()
			s.serveConn(c)
		}()
	}
}

func (s *Session) serveConn(c net.Conn) {
	defer c.Close()
	// Bound a peer that connects and never sends (or never stops sending): a read
	// deadline frees the goroutine, and a LimitReader caps total request bytes.
	_ = c.SetDeadline(time.Now().Add(connTTL))
	br := bufio.NewReader(io.LimitReader(c, maxReqBytes))
	opLine, err := br.ReadString('\n')
	if err != nil && opLine == "" {
		return
	}
	op := strings.TrimSpace(opLine)
	req, err := ParseRequest(op, br)
	if err != nil {
		return // malformed -> empty response, git falls back
	}
	resp, err := s.Handle(req)
	if err != nil {
		return // unauthorized/mint failure -> empty response, never a partial cred
	}
	_, _ = io.WriteString(c, resp)
}

// Query is the in-box side: it dials the per-session socket, forwards one
// credential-helper call (op + the attribute lines git put on stdin), and copies
// the broker's response to out. The box holds NO secret; it only relays the
// request and the short-lived answer. socket is $RUNCLAVE_BROKER_SOCK.
func Query(socket, op string, in io.Reader, out io.Writer) error {
	c, err := net.Dial("unix", socket)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.WriteString(c, op+"\n"); err != nil {
		return err
	}
	if _, err := io.Copy(c, in); err != nil {
		return err
	}
	// Half-close so the server sees EOF on the request and can respond. Without
	// this the server would block reading attributes forever.
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	_, err = io.Copy(out, c)
	return err
}
