package util

import "go.uber.org/zap"

func GetLogger(devMode bool) (*zap.SugaredLogger, error) {
	var _logger *zap.Logger
	var err error
	if devMode {
		_logger, err = zap.NewDevelopment()
	} else {
		_logger, err = zap.NewProduction()
	}
	if err != nil {
		return nil, err
	} else {
		defer _logger.Sync()
		return _logger.Sugar(), nil
	}
}
