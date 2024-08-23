package tag

import "fmt"

type TagID uint32

const (
	// The first 65536 * 2 TagIDs are reserved for tag on exposed ports with number 0~65535
	TIDDstPortZero TagID = iota

	TIDSrcPortZero TagID = iota + 65536
)

const (
	// IdWorld represents any endpoint outside of the cluster
	TIDDstWorld TagID = iota + 65536*2 + 1
	TIDSrcWorld
)

var (
	TagDstWorld = Tag{
		TID:    TIDDstWorld,
		String: "dst:world",
	}
	TagSrcWorld = Tag{
		TID:    TIDSrcWorld,
		String: "src:world",
	}
)

type Tag struct {
	TID    TagID
	String string
}

func GetTagSrcPortN(n uint32) *Tag {
	return &Tag{
		TID:    TIDSrcPortZero + TagID(n),
		String: fmt.Sprintf("src:port-%v", n),
	}
}

func GetTagDstPortN(n uint32) *Tag {
	return &Tag{
		TID:    TIDDstPortZero + TagID(n),
		String: fmt.Sprintf("dst:port-%v", n),
	}
}
