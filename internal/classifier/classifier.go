package classifier

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"github.com/dinoallo/sealos-networkmanager-agent/api/structs"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	"github.com/puzpuzpuz/xsync"
)

type exposedPortTable struct {
	exposedPorts *xsync.MapOf[uint32, bool]
}

func newExposedPortTable() *exposedPortTable {
	return &exposedPortTable{
		exposedPorts: xsync.NewIntegerMapOf[uint32, bool](),
	}
}

type RawTrafficClassifierParams struct {
	conf.ClassifierConfig
}

type RawTrafficClassifier struct {
	podMetaTable      *xsync.MapOf[string, structs.PodMeta]
	exposedPortTables *xsync.MapOf[string, *exposedPortTable]
	hostCIDRs         []netip.Prefix
	skippedCIDRs      []netip.Prefix
	podCIDRs          []netip.Prefix
	RawTrafficClassifierParams
}

func NewRawTrafficClassifer(params RawTrafficClassifierParams) (*RawTrafficClassifier, error) {
	// init skipped cidrs
	var skippedCIDRs []netip.Prefix
	/// if the user specifies skipped cidrs, add them as well
	for _, skippedCIDRStr := range params.SkippedCIDRList {
		prefixes, err := getPrefixes(skippedCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a skipped cidr", skippedCIDRStr, err)
			////TODO: handle me
			continue
		}
		skippedCIDRs = append(skippedCIDRs, prefixes...)
	}
	log.Printf("skipped cidrs: %v", skippedCIDRs)
	// init host cidrs
	var hostCIDRs []netip.Prefix
	/// add user specified host cidrs
	for _, hostCIDRStr := range params.HostCIDRList {
		prefixes, err := getPrefixes(hostCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a host cidr", hostCIDRStr, err)
			continue
		}
		hostCIDRs = append(hostCIDRs, prefixes...)
	}
	log.Printf("host cidrs: %v", hostCIDRs)
	// init pod cidrs
	var podCIDRs []netip.Prefix
	/// add user specified pod cidrs
	for _, podCIDRStr := range params.PodCIDRList {
		prefixes, err := getPrefixes(podCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a pod cidr", podCIDRStr, err)
			continue
		}
		podCIDRs = append(podCIDRs, prefixes...)
	}
	log.Printf("pod cidrs: %v", podCIDRs)
	return &RawTrafficClassifier{
		podMetaTable:               xsync.NewMapOf[structs.PodMeta](),
		exposedPortTables:          xsync.NewMapOf[*exposedPortTable](),
		RawTrafficClassifierParams: params,
		skippedCIDRs:               skippedCIDRs,
		podCIDRs:                   podCIDRs,
		hostCIDRs:                  hostCIDRs,
	}, nil
}

// RegisterPod registers an address under pod network
func (c *RawTrafficClassifier) RegisterPod(addr string, podMeta structs.PodMeta) error {
	c.podMetaTable.Store(addr, podMeta)
	return nil
}

func (c *RawTrafficClassifier) UnregisterPod(addr string) error {
	c.podMetaTable.LoadAndDelete(addr)
	return nil
}

func (c *RawTrafficClassifier) RegisterExposedPort(podAddr string, podPort uint32) error {
	newEPT := newExposedPortTable()
	ept, loaded := c.exposedPortTables.LoadOrStore(podAddr, newEPT)
	if !loaded {
		ept = newEPT
	}
	ept.exposedPorts.Store(podPort, true)
	return nil
}

// TODO: gc the exposedPortTable if the podAddr doesn't have any registerd and exposed ports
func (c *RawTrafficClassifier) UnregisterExposedPort(podAddr string, podPort uint32) error {
	ept, loaded := c.exposedPortTables.Load(podAddr)
	if !loaded {
		return nil
	}
	ept.exposedPorts.LoadAndDelete(podPort)
	return nil
}

func (c *RawTrafficClassifier) CheckAndGetPodMeta(addr string) (structs.PodMeta, bool) {
	podMeta, loaded := c.podMetaTable.Load(addr)
	if !loaded {
		return structs.PodMeta{}, false
	}
	return podMeta, true
}

func (c *RawTrafficClassifier) GetPodMeta(addr string) (structs.PodMeta, bool) {
	podMeta, loaded := c.podMetaTable.Load(addr)
	if !loaded {
		return structs.PodMeta{}, false
	}
	return podMeta, true
}

func (c *RawTrafficClassifier) GetAddrType(addr string) (modules.AddrType, error) {
	if addr == "" {
		return modules.AddrTypeUnknown, nil
	}
	isSkippedAddr, err := c.IsSkippedAddr(addr)
	if err != nil {
		return modules.AddrTypeSkipped, err
	}
	if isSkippedAddr {
		return modules.AddrTypeSkipped, nil
	}
	isPodAddr, err := c.IsPodAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isPodAddr {
		return modules.AddrTypePod, nil
	}
	isHostAddr, err := c.IsHostAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isHostAddr {
		return modules.AddrTypeHost, nil
	}
	return modules.AddrTypeWorld, nil
}

func (c *RawTrafficClassifier) IsPodAddr(addr string) (bool, error) {
	for _, podCIDR := range c.podCIDRs {
		yes, err := inNetwork(podCIDR, addr)
		if err != nil {
			return false, err
		}
		if yes {
			return true, nil
		}
	}
	return false, nil
}

func (c *RawTrafficClassifier) IsHostAddr(addr string) (bool, error) {
	for _, hostCIDR := range c.hostCIDRs {
		yes, err := inNetwork(hostCIDR, addr)
		if err != nil {
			return false, err
		}
		if yes {
			return true, nil
		}
	}
	return false, nil
}

func (c *RawTrafficClassifier) IsSkippedAddr(addr string) (bool, error) {
	for _, skippedCIDR := range c.skippedCIDRs {
		yes, err := inNetwork(skippedCIDR, addr)
		if err != nil {
			return false, err
		}
		if yes {
			return true, nil
		}
	}
	return false, nil
}

func (c *RawTrafficClassifier) IsWorldAddr(addr string) (bool, error) {
	t, err := c.GetAddrType(addr)
	if err != nil {
		return false, err
	}
	if t == modules.AddrTypeWorld {
		return true, nil
	}
	return false, nil
}

func (c *RawTrafficClassifier) IsPortExposed(podAddr string, podPort uint32) (bool, error) {
	ept, loaded := c.exposedPortTables.Load(podAddr)
	if !loaded {
		return false, nil
	}
	_, loaded = ept.exposedPorts.Load(podPort)
	if loaded {
		return true, nil
	}
	return false, nil
}

func (c *RawTrafficClassifier) DumpExposedPorts(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "dumping exposed ports:\n")
	dumpExposedPorts := func(podAddr string, ept *exposedPortTable) bool {
		fmt.Fprintf(w, "dump %v's exposed port:\n", podAddr)
		dump := func(port uint32, v bool) bool {
			fmt.Fprintf(w, "%v is exposed\n", port)
			return true
		}
		if ept != nil {
			ept.exposedPorts.Range(dump)
		} else {
			fmt.Fprintf(w, "why is there a nil exposedPortTable???\n")
		}
		return true
	}
	c.exposedPortTables.Range(dumpExposedPorts)
}

// TODO: maybe put this into netutil
func getPrefixes(prefixStr string, include4In6 bool) ([]netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return nil, nil
	}
	var prefixes []netip.Prefix
	prefixes = append(prefixes, prefix)
	if !include4In6 {
		return prefixes, nil
	}
	if prefix.Addr().Is4() {
		_4In6Addr := netip.AddrFrom16(prefix.Addr().As16())
		prefix2 := netip.PrefixFrom(_4In6Addr, prefix.Bits()+96)
		prefixes = append(prefixes, prefix2)
	}
	return prefixes, nil
}

// TODO: maybe put this into netutil
func inNetwork(prefix netip.Prefix, _addr string) (bool, error) {
	addr, err := netip.ParseAddr(_addr)
	if err != nil {
		return false, err
	}
	return prefix.Contains(addr), nil
}
