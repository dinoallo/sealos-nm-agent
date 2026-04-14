package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPConverting(t *testing.T) {
	t.Run("ipv4 converting", func(t *testing.T) {
		var ip uint32 = 0x0203a8c0
		addr, ok := ToIP(ip, nil, 4)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "192.168.3.2", addr.String())
		}
	})
	// v6Addr1 := "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"
	t.Run("ipv6 converting 1", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0xb80d0120)
		ip = append(ip, 0x44443333)
		ip = append(ip, 0xddddcccc)
		ip = append(ip, 0xffffeeee)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "2001:db8:3333:4444:cccc:dddd:eeee:ffff", addr.String())
		}
	})
	// v6Addr2 := "2001:db8:1::ab9:C0A8:102"
	t.Run("ipv6 converting 2", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0xb80d0120)
		ip = append(ip, 0x00000100)
		ip = append(ip, 0xb90a0000)
		ip = append(ip, 0x0201a8c0)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "2001:db8:1::ab9:c0a8:102", addr.String())
		}
	})
	t.Run("ipv4 in ipv6 converting", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0x00000000)
		ip = append(ip, 0x00000000)
		ip = append(ip, 0xffff0000)
		ip = append(ip, 0x0203a8c0)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "::ffff:192.168.3.2", addr.String())
		}
	})
}
