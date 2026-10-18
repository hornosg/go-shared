package receiver_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hornosg/go-shared/infrastructure/s2stoken/receiver"
)

// N-2: la métrica «en alto» de ADR-006 ante un S2S_DENY_SUB no parseable, cableada por la librería.
func TestDenyListFromEnv(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	gauge := func() float64 {
		t.Helper()
		mfs, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, mf := range mfs {
			if mf.GetName() == "s2s_deny_sub_invalid" {
				return mf.GetMetric()[0].GetGauge().GetValue()
			}
		}
		t.Fatal("s2s_deny_sub_invalid no registrada")
		return 0
	}

	t.Setenv(receiver.EnvDenySub, "sales,pim")
	d := receiver.DenyListFromEnv(reg, log)
	if d.Invalid() || !d.Denies("sales") || d.Denies("webdata") || gauge() != 0 {
		t.Fatalf("lista válida mal cableada: invalid=%v gauge=%v", d.Invalid(), gauge())
	}

	t.Setenv(receiver.EnvDenySub, "sales,") // coma final: falla cerrada
	d = receiver.DenyListFromEnv(reg, log)  // segundo registro en el mismo registro: no es error
	if !d.Invalid() || !d.Denies("webdata") || gauge() != 1 {
		t.Fatalf("lista no parseable: invalid=%v gauge=%v", d.Invalid(), gauge())
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		found = found || mf.GetName() == "s2s_deny_sub_rejections_total"
	}
	if !found {
		t.Fatal("s2s_deny_sub_rejections_total no registrada")
	}
}
