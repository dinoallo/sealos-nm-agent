package mongo

import (
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/common"
	"go.mongodb.org/mongo-driver/bson"
)

func toBSONFilter(s *common.Selector) (*bson.E, error) {
	if s.Sa == nil && s.Sb == nil {
		// ( op K V )
		return &bson.E{
			Key: s.K,
			Value: bson.D{
				bson.E{
					Key:   GetSelectorOpString(s.Op),
					Value: s.V,
				},
			},
		}, nil
	} else if s.Sa != nil && s.Sb != nil {
		// (op Sa Sb)
		filterA, err := toBSONFilter(s.Sa)
		if err != nil {
			return nil, err
		}
		filterB, err := toBSONFilter(s.Sb)
		if err != nil {
			return nil, err
		}
		return &bson.E{
			Key: GetSelectorOpString(s.Op),
			Value: bson.D{
				*filterA,
				*filterB,
			},
		}, nil
	}
	return nil, ErrSelectorConvertFailed
}

func ToBSONFilter(s *common.Selector) (*bson.D, error) {
	filter, err := toBSONFilter(s)
	if err != nil {
		return nil, err
	}
	return &bson.D{
		*filter,
	}, nil
}

// func toBSONFilter(s *common.Selector) (*bson.E, error) {
// 	filter := bson.E{}
// 	if s.A == nil {
// 		key, ok := s.Va.(string)
// 		if !ok {
// 			return nil, ErrSelectorOpAConvertFailed
// 		}
// 		if s.B != nil {
// 			filterB, err := toBSONFilter(s.B)
// 			if err != nil {
// 				return nil, err
// 			}
// 			filter = bson.E{
// 				Key: key,
// 				Value: bson.D{
// 					bson.E{
// 						Key:   GetSelectorOpString(s.Op),
// 						Value: *filterB,
// 					},
// 				},
// 			}
// 		} else {
// 			filter = bson.E{
// 				Key: key,
// 				Value: bson.D{
// 					bson.E{
// 						Key:   GetSelectorOpString(s.Op),
// 						Value: s.Vb,
// 					},
// 				},
// 			}
// 		}
// 	} else if s.A != nil || s.B != nil {
// 		filterA, err := toBSONFilter(s.A)
// 		if err != nil {
// 			return nil, err
// 		}
// 		filterB, err := toBSONFilter(s.B)
// 		if err != nil {
// 			return nil, err
// 		}
// 		filter = bson.E{
// 			Key: GetSelectorOpString(s.Op),
// 			Value: bson.D{
// 				*filterA,
// 				*filterB,
// 			},
// 		}
// 	} else {
// 		return nil, ErrSelectorOpAInvalid
// 	}
// 	return &filter, nil
// }

func GetSelectorOpString(op common.SelectorOp) string {
	switch op {
	case common.SelectorEq:
		return "$eq"
	case common.SelectorGt:
		return "$gt"
	case common.SelectorGte:
		return "$gte"
	case common.SelectorIn:
		return "$in"
	case common.SelectorLt:
		return "$lt"
	case common.SelectorLte:
		return "$lte"
	case common.SelectorNe:
		return "$ne"
	case common.SelectorNin:
		return "$nin"
	case common.SelectorAnd:
		return "$and"
	case common.SelectorNot:
		return "$not"
	case common.SelectorNor:
		return "$nor"
	case common.SelectorOr:
		return "$or"
	default:
		return "$nil"
	}
}
