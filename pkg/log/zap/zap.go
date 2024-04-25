package zap

import (
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/log"
	"go.uber.org/zap"
)

type Zap struct {
	logger *zap.SugaredLogger
}

func (z *Zap) Debug(args ...any) {
	z.logger.Debug(args)
}

func NewZap(devMode bool) (*Zap, error) {
	var _logger *zap.Logger
	var err error
	if devMode {
		_logger, err = zap.NewDevelopment()
	} else {
		_logger, err = zap.NewProduction()
	}
	if err != nil {
		return nil, err
	}
	z := Zap{
		logger: _logger.Sugar(),
	}
	return &z, nil
}

func (z *Zap) Close() error {
	return z.logger.Sync()
}

func (z *Zap) Debugf(template string, args ...any) {
	z.logger.Debugf(template, args)
}

func (z *Zap) Error(args ...any) {
	z.logger.Error(args)
}

func (z *Zap) Errorf(template string, args ...any) {
	z.logger.Errorf(template, args)
}

func (z *Zap) Fatal(args ...any) {
	z.logger.Fatal(args)
}

func (z *Zap) Fatalf(template string, args ...any) {
	z.logger.Fatalf(template, args)
}

func (z *Zap) Info(args ...any) {
	z.logger.Info(args)
}

func (z *Zap) Infof(template string, args ...any) {
	z.logger.Infof(template, args)
}

func (z *Zap) WithCompName(compName string) (log.Logger, error) {
	_logger := z.logger.With("component", compName)
	return &Zap{
		logger: _logger,
	}, nil
}
