package traffic

import "testing"

func TestDeviceSubscribing(t *testing.T) {

}

func TestCloseTrafficObjectsWithPodOnlyObjects(t *testing.T) {
	if err := closeTrafficObjects(&trafficObjects{}); err != nil {
		t.Fatalf("close pod-only traffic objects: %v", err)
	}
}
