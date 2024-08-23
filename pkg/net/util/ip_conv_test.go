package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: this test is not correct...
func TestIPConverting(t *testing.T) {
	t.Run("ipv4 converting", func(t *testing.T) {
		var ip uint32 = 3232236290
		addr, ok := ToIP(ip, nil, 4)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "192.168.3.2", addr.String())
		}
	})
	// v6Addr1 := "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF"
	t.Run("ipv6 converting 1", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0x20010db8)
		ip = append(ip, 0x33334444)
		ip = append(ip, 0xccccdddd)
		ip = append(ip, 0xeeeeffff)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "2001:db8:3333:4444:cccc:dddd:eeee:ffff", addr.String())
		}
	})
	// v6Addr2 := "2001:db8:1::ab9:C0A8:102"
	t.Run("ipv6 converting 2", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0x20010db8)
		ip = append(ip, 0x00010000)
		ip = append(ip, 0x00000ab9)
		ip = append(ip, 0xc0a80102)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "2001:db8:1::ab9:c0a8:102", addr.String())
		}
	})
	t.Run("ipv4 in ipv6 converting", func(t *testing.T) {
		var ip []uint32
		ip = append(ip, 0x00000000)
		ip = append(ip, 0x00000000)
		ip = append(ip, 0x0000ffff)
		ip = append(ip, 0xc0a80302)
		addr, ok := ToIP(0, ip, 6)
		if assert.Equal(t, true, ok) {
			assert.Equal(t, "::ffff:192.168.3.2", addr.String())
		}
	})
}
