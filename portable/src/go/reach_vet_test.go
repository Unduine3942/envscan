package main

import "testing"

func TestPublicHostTrailingDot(t *testing.T) {
	if len(spec.PublicHosts) == 0 {
		t.Skip("no public hosts in the spec")
	}
	h := spec.PublicHosts[0]
	for _, v := range []string{h + ".", "mirror." + h + ".", "MIRROR." + h} {
		if !publicHost(v) || preVet(v) != publicWhy {
			t.Errorf("%s not treated as public", v)
		}
	}
}
