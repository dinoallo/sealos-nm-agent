package common

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrArgumentInvalid = errors.New("invalid arguments")
	ErrSelectorInvalid = errors.New("invalid selector")

	ErrCollectionAlreadyExists = errors.New("this collection already exists")
	ErrCollectionCreateFailed  = errors.New("unable to create the collection")
	ErrCollectionCheckFailed   = errors.New("unable to check if the collection exists")

	ErrPartialTTLIndexAlreadyExists = errors.New("this partial ttl index already exists")
	ErrPartialTTLIndexCreateFailed  = errors.New("unable to create the partial ttl index")
	ErrPartialTTLIndexCheckFailed   = errors.New("unable to check if the partial ttl index exists")
)

type TimeSeriesOpts struct {
	TimeField   string
	MetaField   string
	ExpireAfter int64
}

type PartialTTLIndexOpts struct {
	PartialTTLIndexName     string
	IndexKeys               *Selector
	PartialFilterExpression *Selector
	ExpireAfter             int32
}

type GetOpts struct {
	Size int
}

type Selector struct {
	Op SelectorOp
	Sa *Selector
	Sb *Selector
	K  string
	V  any
}

func (s *Selector) String() string {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("op: %v\n", s.Op))
	builder.WriteString("[\n")
	if s.Sa != nil {
		builder.WriteString(fmt.Sprintf("Sa: %v\n", s.Sa))
	}
	if s.Sb != nil {
		builder.WriteString(fmt.Sprintf("Sb: %v\n", s.Sb))
	}
	if s.K != "" {
		builder.WriteString(fmt.Sprintf("%v", s.K))
	}
	if s.V != nil {
		builder.WriteString(fmt.Sprintf("%v", s.V))
	}
	builder.WriteString("]\n")
	return builder.String()
}

type SelectorOp int

const (
	// comparison ops
	SelectorEq = iota
	SelectorGt
	SelectorGte
	SelectorIn
	SelectorLt
	SelectorLte
	SelectorNe
	SelectorNin
	// logical ops
	SelectorAnd
	SelectorNot
	SelectorNor
	SelectorOr
)

func (op *SelectorOp) String() string {
	//TODO: imple me
	return "op"
}
