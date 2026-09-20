package agent

import (
	"fmt"
	"net/http"
	"strings"
)

func sameOriginRedirect(r *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) >= 5 {
		return fmt.Errorf("redirect limit reached")
	}
	origin := via[0].URL
	if r.URL.User != nil || r.URL.Scheme != origin.Scheme || !strings.EqualFold(r.URL.Host, origin.Host) {
		return fmt.Errorf("cross-origin server redirect rejected")
	}
	return nil
}
