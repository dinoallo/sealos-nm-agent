package hooker

import (
	"testing"
)

func TestCiliumCCMKeyGetting(t *testing.T) {
	// t.Run("v4 ingress test", func(t *testing.T) {
	// 	dir := common.TRAFFIC_DIR_V4_INGRESS
	// 	key, err := getCiliumCCMKey(dir)
	// 	if assert.NoError(t, err, err) {
	// 		assert.Equal(t, key, ciliumCCMapKeyForIngressV4, "the two values should be the same")
	// 	}
	// })
	// t.Run("v4 egress test", func(t *testing.T) {
	// 	dir := common.TRAFFIC_DIR_V4_EGRESS
	// 	key, err := getCiliumCCMKey(dir)
	// 	if assert.NoError(t, err, err) {
	// 		assert.Equal(t, key, ciliumCCMapKeyForEgressV4, "the two values should be the same")
	// 	}
	// })
	// t.Run("v6 ingress test", func(t *testing.T) {
	// 	dir := common.TRAFFIC_DIR_V6_INGRESS
	// 	key, err := getCiliumCCMKey(dir)
	// 	if assert.NoError(t, err, err) {
	// 		assert.Equal(t, key, ciliumCCMapKeyForIngressV6, "the two values should be the same")
	// 	}
	// })
	// t.Run("v6 egress test", func(t *testing.T) {
	// 	dir := common.TRAFFIC_DIR_V6_EGRESS
	// 	key, err := getCiliumCCMKey(dir)
	// 	if assert.NoError(t, err, err) {
	// 		assert.Equal(t, key, ciliumCCMapKeyForEgressV6, "the two values should be the same")
	// 	}
	// })
	// t.Run("unknown test", func(t *testing.T) {
	// 	dir := common.TRAFFIC_DIR_UNKNOWN
	// 	_, err := getCiliumCCMKey(dir)
	// 	assert.Error(t, err, "should return an error")
	// })
}

func TestHookAttaching(t *testing.T) {

}

func TestHookDetaching(t *testing.T) {

}
