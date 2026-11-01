package util

import "testing"

func TestUTCRoundtrip(t *testing.T) {
	for _, ms := range []int64{0, 1_759_579_201_123, 951_782_400_000, 4_102_444_799_999} {
		got, ok := ParseUTC(FmtUTC(ms))
		if !ok || got != ms {
			t.Errorf("%d -> %s -> %d", ms, FmtUTC(ms), got)
		}
	}
	if s := FmtUTC(1_759_579_201_123); s != "2025-10-04T12:00:01.123Z" {
		t.Errorf("FmtUTC = %s", s)
	}
}

func TestParseWhen(t *testing.T) {
	now := NowMs()
	if ms, ok := ParseWhen("2h"); !ok || now-ms < 7_199_000 || now-ms > 7_201_000 {
		t.Errorf("2h = %d", now-ms)
	}
	for _, s := range []string{"2026-10-04", "2026-10-04 13:00", "2026-10-04T13:00:05"} {
		if _, ok := ParseWhen(s); !ok {
			t.Errorf("%q não reconhecido", s)
		}
	}
	if _, ok := ParseWhen("ontem"); ok {
		t.Error("texto inválido aceito")
	}
}
