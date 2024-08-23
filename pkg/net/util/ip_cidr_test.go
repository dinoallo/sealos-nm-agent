package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInNetwork(t *testing.T) {
	t.Run("is this addr in this network? yes", func(t *testing.T) {
		prefix := "192.168.0.0/16"
		addr := "192.168.1.1"
		yes, err := InNetwork(prefix, addr)
		if assert.NoError(t, err) {
			assert.True(t, yes)
		}
	})
	t.Run("is this addr in this network? no", func(t *testing.T) {
		prefix := "192.168.0.0/24"
		addr := "192.168.1.1"
		yes, err := InNetwork(prefix, addr)
		if assert.NoError(t, err) {
			assert.False(t, yes)
		}
	})
}
