package webrtc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/system"
)

// Supported reports whether the kernel can run the NFQUEUE learner.
func Supported(r system.Runner) bool {
	_, _ = r.Run("modprobe", "-q", "nfnetlink_queue")
	_, _ = r.Run("modprobe", "-q", "xt_NFQUEUE")
	b, err := os.ReadFile("/proc/net/ip_tables_targets")
	if err != nil || !strings.Contains(string(b), "NFQUEUE") {
		return false
	}
	_, err = os.Stat("/proc/net/netfilter/nfnetlink_queue")
	return err == nil
}

// PolicyTrack is a policy the tracker serves.
type PolicyTrack struct {
	ID    int
	Queue uint16
	Mark  uint32
}

// Stats are tracker counters for the UI.
type Stats struct {
	Queued  uint64 `json:"queued"`
	STUN    uint64 `json:"stun"`
	Learned uint64 `json:"learned"` // peers
	Servers uint64 `json:"servers"` // STUN/TURN servers
	Errors  uint64 `json:"errors"`
}

// ServerEvent is a STUN/TURN server request seen from a device inside a
// policy session.
type ServerEvent struct {
	Policy int // policy whose queue saw it
	Client string
	Server string
	V6     bool
	Time   time.Time
}

// SessionKey is a device's session window with a policy.
type SessionKey struct {
	Policy int
	Client string
}

// Scan is the result of one conntrack pass.
type Scan struct {
	Time time.Time
	// Active holds known servers (per ServerRoute) with a live connection,
	// whether or not the connection goes through a tunnel.
	Active map[string]bool
	// Sessions holds devices with live policy-marked connections.
	Sessions map[SessionKey]bool
}

// Tracker owns the NFQUEUE sockets and the session refresher.
type Tracker struct {
	IPSet    netfilter.IPSet
	MarkMask uint32
	// ConnMask is where the policy id is in conntrack marks (0: MarkMask).
	ConnMask uint32

	// ServerRoute reports how a known STUN/TURN server is routed: the
	// policy id, or 0 for WAN. known=false means the server is not learned
	// yet; it then follows the session's policy. Called from the packet
	// path: must be fast.
	ServerRoute func(addr string) (policy int, known bool)
	// OnServer receives server requests (from a dedicated goroutine).
	OnServer func(ServerEvent)
	// OnScan receives each conntrack pass.
	OnScan func(Scan)
	// OnPeer receives the peers a client's STUN revealed, batched: they
	// become sessions of that client (routed for it only, while it keeps
	// talking to them).
	OnPeer func(policy int, client string, peers []string) error

	mu       sync.Mutex
	serverCh chan ServerEvent
	cancel   context.CancelFunc
	queues   map[int]*nfqueue.Nfqueue
	tracks   map[int]PolicyTrack
	learnCh  chan learnReq
	stats    map[int]*Stats
	wg       sync.WaitGroup
}

type learnReq struct {
	policy       int
	client, addr string
}

// NewTracker creates a tracker.
func NewTracker(ipset netfilter.IPSet, mask uint32) *Tracker {
	return &Tracker{IPSet: ipset, MarkMask: mask, queues: map[int]*nfqueue.Nfqueue{}, tracks: map[int]PolicyTrack{}, stats: map[int]*Stats{}}
}

// Stats returns a copy of per-policy counters.
func (t *Tracker) Stats() map[int]Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[int]Stats{}
	for id, s := range t.stats {
		out[id] = Stats{Queued: atomic.LoadUint64(&s.Queued), STUN: atomic.LoadUint64(&s.STUN), Learned: atomic.LoadUint64(&s.Learned),
			Servers: atomic.LoadUint64(&s.Servers), Errors: atomic.LoadUint64(&s.Errors)}
	}
	return out
}

// Configure (re)starts queue listeners for the given policies. queue=false
// means the kernel lacks NFQUEUE: only the session refresher runs.
func (t *Tracker) Configure(tracks []PolicyTrack, queue bool) error {
	t.Stop()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(tracks) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.learnCh = make(chan learnReq, 1024)
	t.serverCh = make(chan ServerEvent, 256)
	t.wg.Add(3)
	go t.learner(ctx)
	go t.serverLoop(ctx, t.serverCh)
	go t.refresher(ctx)
	var errs []string
	for _, tr := range tracks {
		t.tracks[tr.ID] = tr
		if t.stats[tr.ID] == nil {
			t.stats[tr.ID] = &Stats{}
		}
		if !queue {
			continue
		}
		if err := t.openQueue(ctx, tr); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (t *Tracker) openQueue(ctx context.Context, tr PolicyTrack) error {
	cfg := nfqueue.Config{
		NfQueue:      tr.Queue,
		MaxPacketLen: 512, // STUN header + a few attributes is all we need
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 50 * time.Millisecond,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	}
	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("nfqueue %d: %w", tr.Queue, err)
	}
	st := t.stats[tr.ID]
	serverCh := t.serverCh
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		atomic.AddUint64(&st.Queued, 1)
		if a.Payload == nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		pk, ok := Parse(*a.Payload)
		if !ok || !pk.UDP || !IsSTUN(pk.Payload) {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		atomic.AddUint64(&st.STUN, 1)
		var orig uint32
		if a.Mark != nil {
			orig = *a.Mark
		}
		v6 := pk.Dst.To4() == nil
		dst := pk.Dst.String()
		src := pk.Src.String()
		if Classify(pk.Payload) == TargetServer {
			atomic.AddUint64(&st.Servers, 1)
			select {
			case serverCh <- ServerEvent{Policy: tr.ID, Client: pk.Src.String(), Server: dst, V6: v6, Time: time.Now()}:
			default:
				atomic.AddUint64(&st.Errors, 1)
			}
			mark := tr.Mark
			if t.ServerRoute != nil {
				if pol, known := t.ServerRoute(dst); known {
					if pol == 0 {
						// The user sent this server's group to WAN.
						_ = nf.SetVerdict(id, nfqueue.NfAccept)
						return 0
					}
					mark = t.policyMark(pol)
				}
			}
			t.repeat(nf, id, orig, mark, st)
			return 0
		}
		t.repeat(nf, id, orig, tr.Mark, st)
		select {
		case t.learnCh <- learnReq{policy: tr.ID, client: src, addr: dst}:
		default:
			atomic.AddUint64(&st.Errors, 1)
		}
		return 0
	}
	errFn := func(e error) int {
		if ctx.Err() != nil {
			return 1
		}
		logx.Debugf("nfqueue %d: %v", tr.Queue, e)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		nf.Close()
		return fmt.Errorf("nfqueue %d register: %w", tr.Queue, err)
	}
	t.queues[tr.ID] = nf
	logx.Infof("webrtc: listening on nfqueue %d for policy %d", tr.Queue, tr.ID)
	return nil
}

// repeat re-runs mangle with the policy mark set; SNAKE sees the mark,
// saves it to the conntrack entry and stops, so the whole flow (and its NAT
// binding) follows the tunnel from the first packet.
func (t *Tracker) repeat(nf *nfqueue.Nfqueue, id, orig, mark uint32, st *Stats) {
	// Clear the Adaptive QoS direction bits too: SNAKE only saves a policy
	// mark from a packet without them.
	if err := nf.SetVerdictWithOption(id, nfqueue.NfRepeat, nfqueue.WithMark(orig&^(t.MarkMask|qosDirMask)|mark)); err != nil {
		atomic.AddUint64(&st.Errors, 1)
	}
}

// qosDirMask is config.QoSDirMask.
const qosDirMask = 0xc0000000

func (t *Tracker) connMask() uint32 {
	if t.ConnMask != 0 {
		return t.ConnMask
	}
	return t.MarkMask
}

func (t *Tracker) policyMark(id int) uint32 {
	return uint32(id) << markShift(t.MarkMask) & t.MarkMask
}

func markShift(mask uint32) uint {
	shift := uint(0)
	for m := mask; m != 0 && m&1 == 0; m >>= 1 {
		shift++
	}
	return shift
}

func (t *Tracker) serverLoop(ctx context.Context, ch chan ServerEvent) {
	defer t.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			if t.OnServer != nil {
				t.OnServer(ev)
			}
		}
	}
}

// learner batches the peers each client's STUN revealed and hands them
// to OnPeer, which makes them sessions of that client.
func (t *Tracker) learner(ctx context.Context) {
	defer t.wg.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	type who struct {
		policy int
		client string
	}
	pending := map[who]map[string]bool{}
	flush := func() {
		for w, addrs := range pending {
			list := make([]string, 0, len(addrs))
			for a := range addrs {
				list = append(list, a)
			}
			sort.Strings(list)
			if t.OnPeer == nil {
				continue
			}
			if err := t.OnPeer(w.policy, w.client, list); err != nil {
				logx.Warnf("webrtc: peers of %s: %v", w.client, err)
				continue
			}
			t.mu.Lock()
			st := t.stats[w.policy]
			t.mu.Unlock()
			if st != nil {
				atomic.AddUint64(&st.Learned, uint64(len(list)))
			}
		}
		pending = map[who]map[string]bool{}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case r := <-t.learnCh:
			k := who{r.policy, r.client}
			if pending[k] == nil {
				pending[k] = map[string]bool{}
			}
			pending[k][r.addr] = true
		case <-tick.C:
			if len(pending) > 0 {
				flush()
			}
		}
	}
}

// refresher keeps session windows open while a client still has live,
// policy-marked connections (e.g. a long-lived signalling websocket or an
// ongoing call), which iptables alone cannot see once flows are offloaded.
// It also re-arms the TTL of learned STUN/TURN servers that still have live
// connections, so a server's TTL only starts counting once it is idle.
func (t *Tracker) refresher(ctx context.Context) {
	defer t.wg.Done()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.refreshOnce()
		}
	}
}

func (t *Tracker) refreshOnce() {
	t.mu.Lock()
	cmask := t.connMask()
	shift := markShift(cmask)
	tracked := map[int]bool{}
	for id := range t.tracks {
		tracked[id] = true
	}
	t.mu.Unlock()
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return
	}
	defer f.Close()
	t.refreshFrom(f, tracked, shift)
}

func (t *Tracker) refreshFrom(f io.Reader, tracked map[int]bool, shift uint) {
	scan := Scan{Time: time.Now(), Active: map[string]bool{}, Sessions: map[SessionKey]bool{}}
	adds := map[string]map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		c, marked, live := parseConn(sc.Text(), t.connMask(), shift)
		if !live {
			continue
		}
		if t.ServerRoute != nil && c.Dst != "" {
			if _, known := t.ServerRoute(c.Dst); known {
				scan.Active[c.Dst] = true
			}
		}
		if !marked || !tracked[c.ID] {
			continue
		}
		scan.Sessions[SessionKey{c.ID, c.Src}] = true
		set := netfilter.SetName(c.ID, netfilter.KindSession, c.V6)
		if adds[set] == nil {
			adds[set] = map[string]bool{}
		}
		adds[set][c.Src] = true
	}
	for set, srcs := range adds {
		list := make([]string, 0, len(srcs))
		for s := range srcs {
			list = append(list, s)
		}
		_ = t.IPSet.AddMany(set, list)
	}
	if t.OnScan != nil {
		t.OnScan(scan)
	}
}

// Conn is a live, policy-marked conntrack entry.
type Conn struct {
	ID       int    // policy id from the connmark
	Src, Dst string // original direction
	V6       bool
}

// ParseConntrack extracts the policy id (from the connmark) and the original
// addresses of an established, policy-marked conntrack line.
func ParseConntrack(line string, mask uint32, shift uint) (Conn, bool) {
	c, marked, live := parseConn(line, mask, shift)
	return c, marked && live
}

// LiveFlow returns the original source and destination of any conntrack
// line that is not a closing TCP connection, marked or not.
func LiveFlow(line string) (src, dst string, ok bool) {
	c, _, live := parseConn(line, 0, 0)
	return c.Src, c.Dst, live && c.Src != "" && c.Dst != ""
}

// parseConn parses any conntrack line. marked: it carries a policy mark;
// live: it is not a closing TCP connection.
func parseConn(line string, mask uint32, shift uint) (c Conn, marked, live bool) {
	f := strings.Fields(line)
	if len(f) < 6 {
		return
	}
	c.V6 = f[0] == "ipv6"
	var mark uint64
	for _, x := range f {
		if c.Src == "" && strings.HasPrefix(x, "src=") {
			c.Src = strings.TrimPrefix(x, "src=")
		}
		if c.Dst == "" && strings.HasPrefix(x, "dst=") {
			c.Dst = strings.TrimPrefix(x, "dst=")
		}
		if strings.HasPrefix(x, "mark=") {
			mark, _ = strconv.ParseUint(strings.TrimPrefix(x, "mark="), 10, 32)
		}
	}
	if c.Src == "" {
		return
	}
	c.Src, c.Dst = canonIP(c.Src), canonIP(c.Dst)
	c.ID = int((uint32(mark) & mask) >> shift)
	marked = c.ID != 0
	// Only established-ish flows keep a session alive.
	live = !strings.Contains(line, " TIME_WAIT ") && !strings.Contains(line, " CLOSE ") && !strings.Contains(line, " FIN_WAIT ")
	return
}

// canonIP normalises an address: /proc/net/nf_conntrack prints IPv6 in full
// form, ipset in compressed form.
func canonIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// Stop closes queues and goroutines.
func (t *Tracker) Stop() {
	t.mu.Lock()
	cancel := t.cancel
	t.cancel = nil
	queues := t.queues
	t.queues = map[int]*nfqueue.Nfqueue{}
	t.tracks = map[int]PolicyTrack{}
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, q := range queues {
		q.Close()
	}
	t.wg.Wait()
}
