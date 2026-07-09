package audit

import (
	"context"
	"testing"
)

// BenchmarkRunFanout measures orchestration overhead with instant fakes:
// the baseline CLAUDE.md asks for on the fleet fan-out hot path.
func BenchmarkRunFanout(b *testing.B) {
	cfg := fleetConfig(b, 100)
	r := &gateReader{}
	opts := Options{Parallel: 10}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(context.Background(), cfg, r, opts)
	}
}
