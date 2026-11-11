package health

import (
	"bytes"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
)

func TestObserve(t *testing.T) {
	var st Status
	st.observe(40*time.Millisecond, nil)
	if st.RTTMs != 40 || st.Loss != 0 {
		t.Fatalf("first sample: %+v", st)
	}
	st.observe(80*time.Millisecond, nil)
	if math.Abs(st.RTTMs-52) > 0.01 {
		t.Fatalf("smoothed rtt %v, want 52", st.RTTMs)
	}
	st.observe(0, errors.New("timeout"))
	if st.ProbeFails != 1 || math.Abs(st.Loss-0.1) > 1e-9 || math.Abs(st.RTTMs-52) > 0.01 {
		t.Fatalf("failure: %+v", st)
	}
	st.observe(52*time.Millisecond, nil)
	if st.ProbeFails != 0 || math.Abs(st.Loss-0.09) > 1e-9 {
		t.Fatalf("recovery: %+v", st)
	}
}

func TestMeasure(t *testing.T) {
	if _, err := measure(bytes.NewReader(make([]byte, 1000))); err == nil {
		t.Fatal("tiny body measured")
	}
	mbps, err := measure(bytes.NewReader(make([]byte, 4<<20)))
	if err != nil || mbps <= 0 {
		t.Fatalf("measure: %v %v", mbps, err)
	}
}

func TestSpeedDue(t *testing.T) {
	s := config.DefaultSettings()
	m := NewMonitor(nil)
	var calls atomic.Int32
	done := make(chan struct{}, 4)
	m.speedTest = func(mark uint32, url string) (float64, error) {
		calls.Add(1)
		done <- struct{}{}
		return 123.4, nil
	}
	m.Set(Status{Tunnel: "wgc1"})
	if sp := m.speedDue(s, "wgc1", false); sp.mbps != 0 {
		t.Fatalf("result before the test ran: %+v", sp)
	}
	<-done
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		running := m.speed["wgc1"].running
		m.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("speed test did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st, _ := m.Get("wgc1"); st.ThroughputMbps != 123.4 || st.SpeedChecked.IsZero() {
		t.Fatalf("status not updated: %+v", st)
	}
	// Not due again within the interval...
	if sp := m.speedDue(s, "wgc1", false); sp.mbps != 123.4 {
		t.Fatalf("cached result: %+v", sp)
	}
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d speed tests, want 1", n)
	}
	// ...but due when the tunnel just became healthy again.
	m.speedDue(s, "wgc1", true)
	<-done
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d speed tests, want 2", n)
	}
	waitIdle := func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			m.mu.Lock()
			running := m.speed["wgc1"].running
			m.mu.Unlock()
			if !running {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("speed test did not finish")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitIdle()
	// ...and when re-checked by hand, once.
	m.RecheckSpeed([]string{"wgc1", "wgc2"})
	if st, _ := m.Get("wgc1"); !st.SpeedTesting {
		t.Fatal("re-checked tunnel not shown as testing")
	}
	m.speedDue(s, "wgc1", false)
	<-done
	waitIdle()
	if st, _ := m.Get("wgc1"); st.SpeedTesting {
		t.Fatal("still shown as testing after the test")
	}
	m.speedDue(s, "wgc1", false)
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 3 {
		t.Fatalf("%d speed tests, want 3", n)
	}
}

func TestSpeedTestHTTP(t *testing.T) {
	body := make([]byte, 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	mbps, err := SpeedTest(0, srv.URL)
	if err != nil && strings.Contains(err.Error(), "operation not permitted") {
		t.Skip("SO_MARK needs CAP_NET_ADMIN")
	}
	if err != nil || mbps <= 0 {
		t.Fatalf("speed test: %v %v", mbps, err)
	}
	if _, err := SpeedTest(0, srv.URL+"/missing"); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("404: %v", err)
	}
}
