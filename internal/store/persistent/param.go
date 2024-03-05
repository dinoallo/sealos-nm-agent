package persistent

import (
	"go.uber.org/zap"
)

type PersistentParam struct {
	ParentLogger *zap.SugaredLogger
	DBURI        string
}
