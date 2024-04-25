package log

type Logger interface {
	Debug(args ...interface{})
	Debugf(template string, args ...interface{})
	Error(args ...interface{})
	Errorf(template string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(template string, args ...interface{})
	Info(args ...interface{})
	Infof(template string, args ...interface{})
	WithCompName(compName string) (Logger, error)
	Close() error
}
