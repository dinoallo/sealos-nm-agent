package hooker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/bpf/common"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/errors/util"
)

var (
	ciliumTCRoot        = filepath.Join(common.BPFFSRoot, "/tc/globals")
	ciliumCCMapTemplate = "cilium_calls_custom_%05d"

	// https://fossies.org/linux/cilium/bpf/custom/README.rst
	ciliumCCMapKeyForIngressV4 = 0
	ciliumCCMapKeyForEgressV4  = 1
	ciliumCCMapKeyForIngressV6 = 2
	ciliumCCMapKeyForEgressV6  = 3
)

// hooker for cilium custom call map
type CiliumCCMHooker struct {
	hook *ebpf.Program
}

func NewCiliumCCMHooker(hook *ebpf.Program) *CiliumCCMHooker {
	return &CiliumCCMHooker{
		hook: hook,
	}
}

func (h *CiliumCCMHooker) AttachHook(ctx context.Context, eid int64, dir common.TrafficDirection) error {
	ccmFile := fmt.Sprintf(ciliumCCMapTemplate, eid)
	ccmPath := filepath.Join(ciliumTCRoot, ccmFile)
	if _, err := os.Stat(ccmPath); errors.Is(err, os.ErrNotExist) {
		return util.Err(ErrCiliumCCMNotExists, err)
	} else if err != nil {
		return util.Err(ErrStatingCiliumCCM, err)
	}
	ccm, err := ebpf.LoadPinnedMap(ccmPath, nil)
	if err != nil {
		return util.Err(ErrLoadingCiliumCCM, err)
	}
	defer ccm.Close()
	key, err := getCiliumCCMKey(dir)
	if err != nil {
		return util.Err(ErrGettingCiliumCCMKey, err)
	}
	if err := ccm.Put(key, h.hook); err != nil {
		return util.Err(ErrUpdatingCiliumCCM, err)
	}
	return nil
}

func (h *CiliumCCMHooker) DetachHook(ctx context.Context, eid int64, dir common.TrafficDirection) error {
	return nil
}

func getCiliumCCMKey(dir common.TrafficDirection) (int, error) {
	switch dir {
	case common.TRAFFIC_DIR_V4_INGRESS:
		return ciliumCCMapKeyForIngressV4, nil
	case common.TRAFFIC_DIR_V4_EGRESS:
		return ciliumCCMapKeyForEgressV4, nil
	case common.TRAFFIC_DIR_V6_INGRESS:
		return ciliumCCMapKeyForIngressV6, nil
	case common.TRAFFIC_DIR_V6_EGRESS:
		return ciliumCCMapKeyForEgressV6, nil
	}
	return 0, common.ErrUnknownTrafficDirection
}
