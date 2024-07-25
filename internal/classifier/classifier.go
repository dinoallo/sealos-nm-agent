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

var (
	defaultPrivateCIDRs = []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fd80::/10",
	}
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
	hostAddrs         *xsync.MapOf[string, struct{}]
	skippedCIDRs      []netip.Prefix
	privateCIDRs      []netip.Prefix
	podCIDRs          []netip.Prefix
	nodeCIDRs         []netip.Prefix
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
	// init pod cidrs
	var podCIDRs []netip.Prefix
	for _, podCIDRStr := range params.PodCIDRList {
		prefixes, err := getPrefixes(podCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a pod cidr", podCIDRStr, err)
			continue
		}
		podCIDRs = append(podCIDRs, prefixes...)
	}
	log.Printf("pod cidrs: %v", podCIDRs)
	// init node cidrs
	var nodeCIDRs []netip.Prefix
	for _, nodeCIDRStr := range params.NodeCIDRList {
		prefixes, err := getPrefixes(nodeCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a node cidr", nodeCIDRStr, err)
			continue
		}
		nodeCIDRs = append(nodeCIDRs, prefixes...)
	}
	log.Printf("node cidrs: %v", nodeCIDRs)
	// init private cidrs
	var privateCIDRs []netip.Prefix
	for _, privateCIDRStr := range defaultPrivateCIDRs {
		prefixes, err := getPrefixes(privateCIDRStr, true)
		if err != nil {
			log.Printf("this cidr expression %v is invalid: %v. it's unable to consider a node cidr", privateCIDRStr, err)
			continue
		}
		privateCIDRs = append(privateCIDRs, prefixes...)
	}
	log.Printf("private cidrs: %v", privateCIDRs)
	return &RawTrafficClassifier{
		podMetaTable:               xsync.NewMapOf[structs.PodMeta](),
		exposedPortTables:          xsync.NewMapOf[*exposedPortTable](),
		hostAddrs:                  xsync.NewMapOf[struct{}](),
		RawTrafficClassifierParams: params,
		skippedCIDRs:               skippedCIDRs,
		podCIDRs:                   podCIDRs,
		nodeCIDRs:                  nodeCIDRs,
		privateCIDRs:               privateCIDRs,
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

func (c *RawTrafficClassifier) RegisterHostAddr(hostAddr string) error {
	c.hostAddrs.LoadOrStore(hostAddr, struct{}{})
	return nil
}

func (c *RawTrafficClassifier) UnregisterHostAddr(hostAddr string) error {
	c.hostAddrs.Delete(hostAddr)
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
		return modules.AddrTypeUnknown, err
	}
	if isSkippedAddr {
		return modules.AddrTypeSkipped, nil
	}
	isHostAddr, err := c.IsHostAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isHostAddr {
		return modules.AddrTypeHost, nil
	}
	isPodAddr, err := c.IsPodAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isPodAddr {
		return modules.AddrTypePod, nil
	}
	isNodeAddr, err := c.IsNodeAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isNodeAddr {
		return modules.AddrTypeNode, nil
	}
	isPrivateAddr, err := c.IsPrivateAddr(addr)
	if err != nil {
		return modules.AddrTypeUnknown, err
	}
	if isPrivateAddr {
		return modules.AddrTypePrivate, err
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

func (c *RawTrafficClassifier) IsNodeAddr(addr string) (bool, error) {
	for _, nodeCIDR := range c.nodeCIDRs {
		yes, err := inNetwork(nodeCIDR, addr)
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
	_, loaded := c.hostAddrs.Load(addr)
	return loaded, nil
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

func (c *RawTrafficClassifier) IsPrivateAddr(addr string) (bool, error) {
	for _, privateCIDR := range c.privateCIDRs {
		yes, err := inNetwork(privateCIDR, addr)
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
