package hooker

import (
	"log"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/bpf/common"
	zaplog "github.com/dinoallo/sealos-networkmanager-agent/pkg/log/zap"
	"github.com/jsimonetti/rtnetlink"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var (
	iface       = "test42"
	hooker      *DeviceHooker
	ingressHook *ebpf.Program
	egressHook  *ebpf.Program
)

func TestFilterOperation(t *testing.T) {
	filterName := "ingress_filter"
	t.Run("add filter on the ingress side", func(t *testing.T) {
		err := hooker.AddFilter(filterName, ingressHook, common.TC_DIR_INGRESS)
		if assert.NoError(t, err) {
		}
	})
	// t.Run("remove filter on the ingress side", func(t *testing.T) {
	// 	err := hooker.RemoveFilter("ingress_filter")
	// 	assert.NoError(t, err)
	// })
	filterName = "egress_filter"
	t.Run("add filter on the egress side", func(t *testing.T) {
		err := hooker.AddFilter(filterName, egressHook, common.TC_DIR_EGRESS)
		assert.NoError(t, err)
	})
	// t.Run("remove filter on the egress side", func(t *testing.T) {
	// 	err := hooker.RemoveFilter("egress_filter")
	// 	assert.NoError(t, err)
	// })
}

func setupDummyInterface(iface string) (*rtnetlink.Conn, error) {
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return &rtnetlink.Conn{}, err
	}
	if err := con.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.ARPHRD_NETROM,
		Index:  0,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: iface,
			Info: &rtnetlink.LinkInfo{Kind: "dummy"},
		},
	}); err != nil {
		return con, err
	}

	return con, err
}

func TestMain(m *testing.M) {
	logger, err := zaplog.NewZap(true)
	if err != nil {
		log.Printf("could not setup log: %v", err)
		return
	}
	testIfAceExists := false
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Errorf("unable to check if testing interface exists: %v", err)
		return
	}
	for _, _iface := range interfaces {
		if _iface.Name == iface {
			testIfAceExists = true
		}
	}
	if !testIfAceExists {
		rtnl, err := setupDummyInterface(iface)
		if err != nil {
			logger.Errorf("could not setup dummy interface: %v", err)
			return
		}
		defer rtnl.Close()
		devID, err := net.InterfaceByName(iface)
		if err != nil {
			logger.Errorf("could not get interface ID: %v", err)
			return
		}
		defer func(ifIndex uint32, rtnl *rtnetlink.Conn) {
			if err := rtnl.Link.Delete(ifIndex); err != nil {
				logger.Errorf("could not delete interface: %v\n", err)
				return
			}
		}(uint32(devID.Index), rtnl)
	}

	spec := ebpf.ProgramSpec{
		Name: "test",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			// Set exit code to 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	}

	// Load the eBPF program into the kernel.
	prog, err := ebpf.NewProgram(&spec)
	if err != nil {
		logger.Errorf("failed to load eBPF program: %v\n", err)
		return
	}
	ingressHook = prog
	egressHook = prog
	hooker, err = NewDeviceHooker(iface, logger)
	if err != nil {
		logger.Error("failed to create a device hooker for testing: %v", err)
		return
	}
	if err := hooker.Init(); err != nil {
		logger.Errorf("failed to initialize the device hooker: %v", err)
		return
	}
	defer func() {
		if err := hooker.Close(); err != nil {
			logger.Error(err)
			return
		}
	}()
	m.Run()
	// os.Exit(code)
}
