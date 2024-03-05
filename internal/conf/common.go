package conf

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/dinoallo/sealos-networkmanager-agent/internal/util"
	"go.uber.org/zap"
)

func printYamlConfig(logger *zap.SugaredLogger, conf interface{}) error {
	if logger == nil {
		return util.ErrLoggerNotInited
	}
	rt := reflect.TypeOf(conf)
	rv := reflect.ValueOf(conf)
	if rt.Kind() != reflect.Struct {
		return fmt.Errorf("the conf is not a struct")
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		fv := rv.FieldByName(f.Name).Interface()
		ft := strings.Split(f.Tag.Get("yaml"), ",")[0]
		logger.Debugf("%v:%v", ft, fv)
	}
	return nil
}
