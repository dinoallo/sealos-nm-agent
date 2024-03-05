package bytecount

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	consts "github.com/dinoallo/sealos-networkmanager-agent/internal/common/const"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.uber.org/zap"
)

func (bf *BytecountFactory) createCounter(ctx context.Context, eid int64, dir consts.TrafficDirection) error {
	c := bf.getCounter(dir)
	if c == nil {
		return nil
	}
	log := bf.logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
	// check and load the custom call map for this endpoint. if the ccm doesn't exist, (may due to the migration for cilium configuration, which leads to new endpoints have ccm while others don't)
	// we inform the caller by returning a special error
	ccmPath := fmt.Sprintf(c.CustomCallPathTemplate, eid)
	if _, err := os.Stat(ccmPath); errors.Is(err, os.ErrNotExist) {
		log.Errorf("unable to find the custom hook map for the endpoint: %v", err)
		return util.ErrBPFCustomCallMapNotExist
	}
	ccm, err := ebpf.LoadPinnedMap(ccmPath, nil)

	if err != nil {
		log.Errorf("unable to load the custom hook map for the endpoint: %v", err)
		return util.ErrBPFMapNotLoaded
	}
	defer ccm.Close()

	prog := c.ClsProgram
	if err := ccm.Put(c.CustomCallMapKey, prog); err != nil {
		log.Errorf("unable to update the custom hook map for the endpoint: %v", err)
		return util.ErrBPFMapNotUpdated
	}

	log.Debugf("counter created")
	return nil
}

func (bf *BytecountFactory) removeCounter(ctx context.Context, eid int64, dir consts.TrafficDirection) error {
	c := bf.getCounter(dir)
	if c == nil {
		return nil
	}
	pinPath := fmt.Sprintf(c.PinPathTemplate, eid)
	log := bf.logger.With(zap.Int64("endpoint", eid), zap.String("direction", c.TypeStr))
	if flag, err := checkCounterExists(pinPath); err == nil && flag == true {
		if counterRemoveError := removeCounterMap(pinPath); counterRemoveError != nil {
			log.Errorf("unable to remove counter program for the endpoint: %v", err)
			return util.ErrBPFMapNotRemoved
		}

	} else if err != nil {
		log.Errorf("unable to check if the counter exist: %v", err)
		return util.ErrBPFMapFailedToCheck
	}

	log.Debugf("counter removed")
	return nil
}

func (bf *BytecountFactory) getCounter(dir consts.TrafficDirection) *Counter {
	var c Counter
	switch dir {
	case consts.TRAFFIC_DIR_V4_INGRESS:
		c = bf.v4IngressCounter
	case consts.TRAFFIC_DIR_V4_EGRESS:
		c = bf.v4EgressCounter
	default:
		return nil
	}
	return &c
}

func checkCounterExists(pinPath string) (bool, error) {
	if _, err := os.Stat(pinPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func removeCounterMap(pinPath string) error {
	err := os.Remove(pinPath)
	return err
}
