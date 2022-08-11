package dns

import (
	"testing"
)

func TestLookupCAA(t *testing.T) {
	for _, dnss := range []string{
		"114.114.114.114:53",
		"223.5.5.5:53",
		"8.8.8.8:53",
	} {
		caas, err := LookupCAA("caa1.hchen90.xyz", dnss)
		if err != nil {
			t.Error(err)
		} else {
			if len(caas) > 0 {
				t.Log(caas)
			}
		}
	}
}
