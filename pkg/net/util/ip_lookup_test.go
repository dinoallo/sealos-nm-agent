package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGettingOutBoundIP(t *testing.T) {
	t.Run("get the outbound ip by asking a v4 dns service", func(t *testing.T) {
		dnsService := "8.8.8.8:80"
		prefixes, err := GetOutboundV4AddrsInCIDR(dnsService, true)
		if assert.NoError(t, err) {
			for _, prefix := range prefixes {
				t.Logf("the outbound ip is: %v", prefix)
			}
		}
	})
	// Disable this temporarily since some environments may not have ipv6 connectivity, and the failure of this test may cause confusion.
	// We can re-enable it after we find a better way to test ipv6 connectivity in different environments.
	// t.Run("get the outbound ip by asking a v6 dns service", func(t *testing.T) {
	// 	dnsService := "[2001:4860:4860::8888]:80"
	// 	prefixes, err := GetOutboundV6AddrsInCIDR(dnsService)
	// 	if assert.NoError(t, err) {
	// 		for _, prefix := range prefixes {
	// 			t.Logf("the outbound ip is: %v", prefix)
	// 		}
	// 	}
	// })
}
