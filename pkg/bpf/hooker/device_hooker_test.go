package hooker

import (
	"log"
	"net"
	"os"
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
		log.Fatalf("could not setup log: %v", err)
	}
	testIfAceExists := false
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("unable to check if testing interface exists: %v", err)
	}
	for _, _iface := range interfaces {
		if _iface.Name == iface {
			testIfAceExists = true
		}
	}
	if !testIfAceExists {
		rtnl, err := setupDummyInterface(iface)
		if err != nil {
			logger.Fatalf("could not setup dummy interface: %v\n", err)
		}
		defer rtnl.Close()
		// TODO: delete device after test completes

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
		logger.Fatalf("failed to load eBPF program: %v\n", err)
	}
	ingressHook = prog
	egressHook = prog
	hooker, err = NewDeviceHooker(iface, logger)
	if err != nil {
		logger.Fatal(err)
	}
	code := m.Run()
	if err := hooker.Close(); err != nil {
		logger.Error(err)
	}
	os.Exit(code)
}
