package net

import "net"

type NetLib interface {
	Interfaces() ([]net.Interface, error)
}

type GoNetLib struct {
}

func NewGoNetLib() *GoNetLib {
	return &GoNetLib{}
}

func (l *GoNetLib) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
