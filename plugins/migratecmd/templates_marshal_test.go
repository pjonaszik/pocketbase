package migratecmd

import (
	"encoding/json/v2"
	"testing"
)

func TestMarshalWithoutEscapeRoundTrip(t *testing.T) {
	cases := []string{
		"café",           // real unicode must appear raw and round-trip
		`litꯍ_end`,       // literal backslash-u + valid hex must be preserved verbatim
		`bad\uZZ`,        // literal backslash-u + non-hex must not error/corrupt
		`has\dbackslash`, // plain backslash control
	}
	for _, in := range cases {
		out, err := marhshalWithoutEscape(in, "  ", "  ")
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", in, err)
		}
		var back string
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("%q: output not valid json: %q (%v)", in, out, err)
		}
		if back != in {
			t.Fatalf("round trip corrupted value:\n  in : %q\n  out: %s\n  back: %q", in, out, back)
		}
	}
}
