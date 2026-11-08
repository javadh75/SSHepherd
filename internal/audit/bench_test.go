package audit

// Fleet fan-out benchmarks.
//
// Methodology: run with -count=10 and a fixed GOMAXPROCS, compare via
// benchstat. For lat>0 cells read the x-ideal metric (measured wall divided
// by the analytic ideal ceil(n/p)*lat), not raw ns/op — sleep-based cells are
// wall-clock sensitive on loaded machines, but the ratio is robust. For lat=0
// cells read sched-ns/server (pool/scheduling overhead per server); those are
// the deterministic regression-tracking cells.
//
// Note on baselines: benchstat matches full benchmark names, so these
// sub-benchmark cells (BenchmarkRunFanout/n=.../p=.../lat=...) do not diff
// against any baseline recorded under the old flat BenchmarkRunFanout name.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// benchIdealBudget caps the analytic ideal wall time of a latency cell. Cells
// above it are skipped: their wall time is latency-dominated and analytically
// ceil(n/p)*lat, so running them adds minutes to `make bench` without signal —
// the sweep's job is only to prove the pool tracks that ideal.
const benchIdealBudget = 2 * time.Second

// benchReader is a minimal KeyReader for benchmarks: fixed content plus an
// optional simulated read latency. Unlike gateReader it keeps no tracking
// atomics, so zero-latency cells measure pure pool/scheduling overhead
// without contended CAS loops.
//
// The latency sleep deliberately ignores ctx, violating KeyReader's
// honor-ctx contract. That is safe for these cells because every benchmark
// using benchReader runs with no PerServerTimeout and a never-cancelled
// context, so nothing ever waits on cancellation and the sleep is bounded at
// latency per read.
type benchReader struct {
	content []byte
	latency time.Duration
}

func (r *benchReader) ReadAuthorizedKeys(_ context.Context, _ config.Server) (fleet.ReadResult, error) {
	if r.latency > 0 {
		time.Sleep(r.latency)
	}
	return fleet.ReadResult{Content: r.content}, nil
}

// benchFleetConfig builds an n-server config for benchmarks. Separate from
// fleetConfig because tests assert fleetConfig's srv-%02d names
// (TestRunDeterministicOrder), while n=1000 fleets need %04d padding.
func benchFleetConfig(b *testing.B, n int) *config.Config {
	b.Helper()
	var sb strings.Builder
	sb.WriteString("servers:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "  - {name: srv-%04d, host: 10.0.%d.%d, user: deploy}\n", i, i/256, i%256)
	}
	cfg, err := config.Parse([]byte(sb.String()))
	if err != nil {
		b.Fatalf("benchFleetConfig: %v", err)
	}
	return cfg
}

// BenchmarkRunFanout sweeps the fan-out over fleet size x pool size x
// simulated per-read latency. lat=0 cells measure orchestration overhead;
// lat>0 cells measure how closely the pool tracks perfect pipelining.
// n=10 runs only at lat=0: a 10-server fleet with latency carries no signal
// beyond what n=100 already shows.
func BenchmarkRunFanout(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		cfg := benchFleetConfig(b, n)
		for _, p := range []int{1, 10, 32, 128} {
			for _, lat := range []time.Duration{0, 10 * time.Millisecond, 100 * time.Millisecond} {
				if n == 10 && lat > 0 {
					continue
				}
				waves := (n + p - 1) / p
				ideal := time.Duration(waves) * lat
				b.Run(fmt.Sprintf("n=%d/p=%d/lat=%s", n, p, lat), func(b *testing.B) {
					if ideal > benchIdealBudget {
						b.Skipf("ideal wall %s (ceil(%d/%d)=%d waves x %s) exceeds budget %s; latency-dominated, no signal",
							ideal, n, p, waves, lat, benchIdealBudget)
					}
					r := &benchReader{latency: lat}
					opts := Options{Parallel: p}
					ctx := context.Background()
					for b.Loop() {
						Run(ctx, cfg, r, opts)
					}
					// Derived metrics computed once after the loop from
					// b.Elapsed()/b.N — never inside the timed region.
					perOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
					if lat == 0 {
						b.ReportMetric(perOp/float64(n), "sched-ns/server")
					} else {
						b.ReportMetric(perOp/float64(ideal.Nanoseconds()), "x-ideal")
					}
				})
			}
		}
	}
}

// benchAuthKeysBody builds a deterministic authorized_keys body with `keys`
// key lines, each preceded by a comment line and followed by a blank line.
// testkeys.Line seeds are a single byte (max 256 distinct keys), so for
// larger corpora identity would have to come from the comment, not the key;
// here keys <= 256 so every key is distinct.
func benchAuthKeysBody(b *testing.B, keys int) []byte {
	b.Helper()
	var sb strings.Builder
	for i := 0; i < keys; i++ {
		fmt.Fprintf(&sb, "# key %d\n%s user%d@bench\n\n", i, testkeys.Line(b, byte(i)), i)
	}
	return []byte(sb.String())
}

// BenchmarkRunFanoutParseHeavy makes each read return a 100-line
// authorized_keys body at zero latency, so per-server work is CPU-bound
// parse+diff. Throughput should flatten once p reaches GOMAXPROCS — evidence
// that --parallel should be sized for network latency, not core count.
func BenchmarkRunFanoutParseHeavy(b *testing.B) {
	const n = 100
	cfg := benchFleetConfig(b, n)
	content := benchAuthKeysBody(b, 100) // shared across p; built once, outside timers
	for _, p := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("p=%d", p), func(b *testing.B) {
			r := &benchReader{content: content}
			opts := Options{Parallel: p}
			ctx := context.Background()
			for b.Loop() {
				Run(ctx, cfg, r, opts)
			}
		})
	}
}

// BenchmarkRunFanoutStragglers validates the straggler cost model
// wall ≈ PerServerTimeout × ceil(hung/p) + base: each hung server occupies a
// pool slot for a full timeout, so they drain in waves. With hung=25, p=10,
// timeout=20ms the expected wall is ceil(25/10)=3 waves ≈ 3×20ms + base.
// This formula drives the default-timeout decision: at production defaults
// (30s timeout, p=10), 25 unreachable hosts add ~90s to every audit.
func BenchmarkRunFanoutStragglers(b *testing.B) {
	const (
		n       = 100
		hung    = 25
		p       = 10
		timeout = 20 * time.Millisecond
	)
	cfg := benchFleetConfig(b, n)
	block := make(map[string]bool, hung)
	for i := 0; i < hung; i++ {
		block[cfg.Servers[i].Name] = true
	}
	r := &gateReader{block: block}
	opts := Options{Parallel: p, PerServerTimeout: timeout}
	ctx := context.Background()
	for b.Loop() {
		Run(ctx, cfg, r, opts)
	}
	waves := (hung + p - 1) / p
	expected := time.Duration(waves) * timeout
	// Computed once after the loop from b.Elapsed()/b.N — never inside the
	// timed region. x-expected ≈ 1 confirms the wave model.
	perOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	b.ReportMetric(perOp/float64(expected.Nanoseconds()), "x-expected")
}
