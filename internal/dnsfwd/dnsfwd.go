// Package dnsfwd runs local DNS forwarders that turn dnsmasq's plain queries
// for policy domains into DNS over TLS (RFC 7858) or DNS over HTTPS
// (RFC 8484) queries to the policy's resolver.
//
// Each forwarder listens on 127.0.0.1 (UDP and TCP). The resolver is dialled
// by IP with the selected tunnel's socket mark; policy routing sends that
// connection through that tunnel, independently of other policies using the
// same resolver. The ISP sees neither
// the query nor that it is DNS, and the resolver sees the VPN exit address.
package dnsfwd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irisariuan/snake/internal/logx"
)

// Protocols.
const (
	DoT = "dot"
	DoH = "doh"
)

// Upstream is an encrypted resolver.
type Upstream struct {
	Proto    string // dot | doh
	IP       string // dialled directly (no bootstrap lookup)
	Port     int    // 0 = 853 (DoT) / 443 (DoH)
	TLSName  string // certificate name, also the DoH Host
	Path     string // DoH path
	Mark     uint32 // tunnel probe mark; independent of the resolver IP
	Iface    string // bind to the tunnel too, so missing rules cannot leak to WAN
	Disabled bool   // no healthy tunnel: SERVFAIL without dialing
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
}

func (u Upstream) addr() string {
	p := u.Port
	if p == 0 {
		p = 853
		if u.Proto == DoH {
			p = 443
		}
	}
	return net.JoinHostPort(u.IP, strconv.Itoa(p))
}

func (u Upstream) String() string {
	if u.Proto == DoH {
		return "https://" + u.TLSName + u.Path + " @" + u.IP
	}
	return "tls://" + u.TLSName + " @" + u.IP
}

// Spec is one forwarder.
type Spec struct {
	ID     int    // policy id
	Listen string // host:port
	Up     Upstream
}

// Stats are a forwarder's counters.
type Stats struct {
	Upstream  string    `json:"upstream"`
	Listen    string    `json:"listen"`
	Queries   uint64    `json:"queries"`
	Errors    uint64    `json:"errors"`
	AvgMS     float64   `json:"avg_ms"`
	LastError string    `json:"last_error,omitempty"`
	LastErrAt time.Time `json:"last_error_at,omitempty"`
}

const queryTimeout = 5 * time.Second

// exchanger sends one DNS message and returns the answer.
type exchanger interface {
	exchange(ctx context.Context, q []byte) ([]byte, error)
	close()
}

func tlsConfig(u Upstream) *tls.Config {
	c := &tls.Config{ServerName: u.TLSName, MinVersion: tls.VersionTLS12, RootCAs: u.RootCAs}
	if u.Proto == DoH {
		c.NextProtos = []string{"h2", "http/1.1"}
	}
	return c
}

// ---------- DoT ----------

type dot struct {
	up   Upstream
	pool chan *tls.Conn
}

func newDoT(u Upstream) *dot { return &dot{up: u, pool: make(chan *tls.Conn, 4)} }

func (d *dot) dial(ctx context.Context) (*tls.Conn, error) {
	nd := upstreamDialer(d.up, queryTimeout)
	raw, err := nd.DialContext(ctx, "tcp", d.up.addr())
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, tlsConfig(d.up))
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func (d *dot) exchange(ctx context.Context, q []byte) ([]byte, error) {
	// A pooled connection may have been closed by the server while idle:
	// on failure retry once on a fresh one.
	for attempt := 0; attempt < 2; attempt++ {
		var c *tls.Conn
		fresh := false
		select {
		case c = <-d.pool:
		default:
		}
		if c == nil {
			var err error
			if c, err = d.dial(ctx); err != nil {
				return nil, err
			}
			fresh = true
		}
		resp, err := dotRoundTrip(ctx, c, q)
		if err == nil {
			select {
			case d.pool <- c:
			default:
				c.Close()
			}
			return resp, nil
		}
		c.Close()
		if fresh {
			return nil, err
		}
	}
	return nil, errors.New("dot: no connection")
}

func dotRoundTrip(ctx context.Context, c *tls.Conn, q []byte) ([]byte, error) {
	dl := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = c.SetDeadline(dl)
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	for {
		resp, err := readMsg(c)
		if err != nil {
			return nil, err
		}
		// Skip a stale answer left over from a timed-out query.
		if len(resp) >= 2 && resp[0] == q[0] && resp[1] == q[1] {
			return resp, nil
		}
	}
}

func readMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (d *dot) close() {
	for {
		select {
		case c := <-d.pool:
			c.Close()
		default:
			return
		}
	}
}

// ---------- DoH ----------

type doh struct {
	up  Upstream
	url string
	hc  *http.Client
	tr  *http.Transport
}

func newDoH(u Upstream) *doh {
	tr := &http.Transport{
		Proxy: nil, // never through an HTTP proxy: the tunnel is the path
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			nd := upstreamDialer(u, queryTimeout)
			return nd.DialContext(ctx, "tcp", u.addr()) // always the configured IP
		},
		TLSClientConfig:     tlsConfig(u),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: queryTimeout,
	}
	return &doh{up: u, url: "https://" + u.TLSName + u.Path, tr: tr, hc: &http.Client{Transport: tr, Timeout: queryTimeout}}
}

func (d *doh) exchange(ctx context.Context, q []byte) ([]byte, error) {
	// RFC 8484: use ID 0 (cache friendly); restore the client's ID after.
	body := append([]byte(nil), q...)
	id0, id1 := body[0], body[1]
	body[0], body[1] = 0, 0
	req, err := http.NewRequestWithContext(ctx, "POST", d.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, errors.New("doh: short answer")
	}
	b[0], b[1] = id0, id1
	return b, nil
}

func (d *doh) close() { d.tr.CloseIdleConnections() }

// ---------- server ----------

type server struct {
	spec   Spec
	ex     exchanger
	udp    net.PacketConn
	tcp    net.Listener
	sem    chan struct{}
	wg     sync.WaitGroup
	cancel context.CancelFunc

	queries, errs, totalNS atomic.Uint64
	mu                     sync.Mutex
	lastErr                string
	lastErrAt              time.Time
}

func start(sp Spec) (*server, error) {
	var ex exchanger
	switch sp.Up.Proto {
	case DoT:
		ex = newDoT(sp.Up)
	case DoH:
		ex = newDoH(sp.Up)
	default:
		return nil, fmt.Errorf("dnsfwd: unknown protocol %q", sp.Up.Proto)
	}
	udp, tcp, err := listenPair(sp.Listen)
	if err != nil {
		ex.close()
		return nil, fmt.Errorf("dns forwarder for policy %d: %w", sp.ID, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{spec: sp, ex: ex, udp: udp, tcp: tcp, sem: make(chan struct{}, 64), cancel: cancel}
	s.wg.Add(2)
	go s.serveUDP(ctx)
	go s.serveTCP(ctx)
	logx.Infof("dns forwarder for policy %d on %s -> %s", sp.ID, udp.LocalAddr(), sp.Up)
	return s, nil
}

// Reserve both transports together, without taking another service's port.
// Never use mDNS's port 5353, even when it is currently unoccupied.
func listenPair(preferred string) (net.PacketConn, net.Listener, error) {
	host, port, err := net.SplitHostPort(preferred)
	if err != nil {
		return nil, nil, err
	}
	addr := preferred
	if port == "5353" {
		addr = net.JoinHostPort(host, "0")
	}
	for attempt := 0; attempt < 32; attempt++ {
		udp, err := net.ListenPacket("udp", addr)
		if err != nil {
			if !errors.Is(err, syscall.EADDRINUSE) {
				return nil, nil, err
			}
			addr = net.JoinHostPort(host, "0")
			continue
		}
		tcp, err := net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			return udp, tcp, nil
		}
		udp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, err
		}
		addr = net.JoinHostPort(host, "0")
	}
	return nil, nil, errors.New("could not reserve a UDP/TCP DNS listener pair")
}

func (s *server) resolve(ctx context.Context, q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("short query")
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	t0 := time.Now()
	s.queries.Add(1)
	var resp []byte
	var err error
	if s.spec.Up.Disabled {
		err = errors.New("no healthy tunnel for DNS")
	} else {
		resp, err = s.ex.exchange(ctx, q)
	}
	if err != nil {
		s.errs.Add(1)
		s.mu.Lock()
		s.lastErr, s.lastErrAt = err.Error(), time.Now()
		s.mu.Unlock()
		logx.Debugf("dns forwarder %d: %v", s.spec.ID, err)
		return servfail(q), err
	}
	s.totalNS.Add(uint64(time.Since(t0)))
	return resp, nil
}

// servfail turns a query into a SERVFAIL answer so dnsmasq gives up at
// once instead of waiting (and never falls back to plain DNS).
func servfail(q []byte) []byte {
	end := 12
	// Keep the question section when it parses; otherwise header only.
	if qd := binary.BigEndian.Uint16(q[4:6]); qd == 1 {
		i := 12
		for i < len(q) && q[i] != 0 {
			i += int(q[i]) + 1
		}
		if i+5 <= len(q) {
			end = i + 5
		}
	}
	r := append([]byte(nil), q[:end]...)
	r[2] = 0x80 | (q[2] & 0x79) // QR, keep opcode and RD
	r[3] = 0x80 | 2             // RA, RCODE=SERVFAIL
	if end == 12 {
		r[4], r[5] = 0, 0
	}
	r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
	return r
}

func (s *server) serveUDP(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
		default:
			continue // overloaded: dnsmasq retries
		}
		go func() {
			defer func() { <-s.sem }()
			resp, _ := s.resolve(ctx, q)
			_, _ = s.udp.WriteTo(resp, addr)
		}()
	}
}

func (s *server) serveTCP(ctx context.Context) {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				q, err := readMsg(c)
				if err != nil {
					return
				}
				resp, _ := s.resolve(ctx, q)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

func (s *server) stop() {
	s.cancel()
	s.udp.Close()
	s.tcp.Close()
	s.wg.Wait()
	s.ex.close()
}

func (s *server) stats() Stats {
	st := Stats{Upstream: s.spec.Up.String(), Listen: s.udp.LocalAddr().String(), Queries: s.queries.Load(), Errors: s.errs.Load()}
	if ok := st.Queries - st.Errors; ok > 0 {
		st.AvgMS = float64(s.totalNS.Load()) / float64(ok) / 1e6
	}
	s.mu.Lock()
	st.LastError, st.LastErrAt = s.lastErr, s.lastErrAt
	s.mu.Unlock()
	return st
}

// ---------- manager ----------

// Manager runs the forwarders of all policies.
type Manager struct {
	mu   sync.Mutex
	srvs map[int]*server
}

// Configure starts, restarts and stops forwarders to match specs.
func (m *Manager) Configure(specs []Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srvs == nil {
		m.srvs = map[int]*server{}
	}
	want := map[int]Spec{}
	for _, sp := range specs {
		want[sp.ID] = sp
	}
	for id, s := range m.srvs {
		if sp, ok := want[id]; !ok || !sameSpec(sp, s.spec) {
			s.stop()
			delete(m.srvs, id)
		}
	}
	var errs []string
	ids := make([]int, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if _, ok := m.srvs[id]; ok {
			continue
		}
		s, err := start(want[id])
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		m.srvs[id] = s
	}
	if len(errs) > 0 {
		return errors.New(joinErrs(errs))
	}
	return nil
}

func sameSpec(a, b Spec) bool {
	return a.Listen == b.Listen && a.Up.Proto == b.Up.Proto && a.Up.IP == b.Up.IP && a.Up.Port == b.Up.Port &&
		a.Up.TLSName == b.Up.TLSName && a.Up.Path == b.Up.Path && a.Up.RootCAs == b.Up.RootCAs && a.Up.Mark == b.Up.Mark && a.Up.Iface == b.Up.Iface && a.Up.Disabled == b.Up.Disabled
}

func joinErrs(errs []string) string {
	var b bytes.Buffer
	for i, e := range errs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(e)
	}
	return b.String()
}

// Stop stops every forwarder.
func (m *Manager) Stop() { _ = m.Configure(nil) }

// Stats returns the counters by policy id.
func (m *Manager) Stats() map[int]Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int]Stats{}
	for id, s := range m.srvs {
		out[id] = s.stats()
	}
	return out
}

// Endpoints contains only successfully bound listeners, in dnsmasq syntax.
func (m *Manager) Endpoints() map[int]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int]string{}
	for id, s := range m.srvs {
		host, port, _ := net.SplitHostPort(s.udp.LocalAddr().String())
		out[id] = host + "#" + port
	}
	return out
}
