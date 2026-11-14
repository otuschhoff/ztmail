//go:build native_smoke

package mail

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestNativeSmokeTLSRootAndGraceScope(t *testing.T) {
	if roots, err := serverRoots(ServerTrust{Mode: RootsSystem}); err != nil || roots == nil {
		t.Fatalf("native system trust unavailable: %v", err)
	}
	ca, _ := tlsBenchCertificate(t, "native-smoke-root", true, nil, nil)
	native := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	for _, mode := range []RootMode{RootsSystem, RootsAppend, RootsReplace} {
		t.Run(string(mode), func(t *testing.T) {
			trust := ServerTrust{Mode: mode, ExpiredServerCertificateGrace: time.Hour}
			if mode != RootsSystem {
				trust.Certificates = [][]byte{ca.Raw}
			}
			prepared, err := cloneServerTrust(trust)
			if native && mode != RootsReplace {
				if !errors.Is(err, ErrTLSFeatureUnavailable) {
					t.Fatalf("native-root expiry-grace limitation lost: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if roots, err := serverRoots(prepared); err != nil || roots == nil {
				t.Fatalf("explicit trust policy unavailable: %v", err)
			}
		})
	}
}
