package net

import (
	"errors"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	ErrFailedToFindInterface = errors.New("failed to find the interface")
	ErrInterfaceNotExists    = errors.New("the interface doesn't exist")
)

type NetLib interface {
	Interfaces() ([]net.Interface, error)
	AddrsByLinkName(linkName string) ([]netip.Addr, error)
}

type NMNetLib struct {
}

func NewNMNetLib() *NMNetLib {
	return &NMNetLib{}
}

func (l *NMNetLib) Interfaces() ([]net.Interface, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var ifaces []net.Interface
	for _, link := range links {
		iface := net.Interface{
			Index:        link.Attrs().Index,
			MTU:          link.Attrs().MTU,
			Name:         link.Attrs().Name,
			Flags:        link.Attrs().Flags,
			HardwareAddr: link.Attrs().HardwareAddr,
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func (l *NMNetLib) AddrsByLinkName(linkName string) ([]netip.Addr, error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		switch err.(type) {
		case netlink.LinkNotFoundError:
			return nil, errors.Join(err, ErrInterfaceNotExists)
		default:
			return nil, errors.Join(err, ErrFailedToFindInterface)
		}
	}
	addrs, err := netlink.AddrList(link, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	var netipAddrs []netip.Addr
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		netipAddr, err := netip.ParseAddr(addr.IP.String())
		if err != nil {
			return nil, err
		}
		netipAddrs = append(netipAddrs, netipAddr)
	}
	return netipAddrs, nil
}
