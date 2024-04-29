package zap

import "testing"

var (
	logger *Zap
)

func TestDebugPrinting(t *testing.T) {
	t.Run("debug", func(t *testing.T) {
		logger.Debug("test debug printing")
	})
	t.Run("debugf", func(t *testing.T) {
		logger.Debugf("test debugf printing: %v", "only arg")
	})
	t.Run("debugf multiple args", func(t *testing.T) {
		logger.Debugf("test debugf printing: %v, %v, %v", "first arg", "second arg", "third arg")
	})
}

func TestMain(m *testing.M) {
	_logger, err := NewZap(true)
	if err != nil {
		return
	}
	logger = _logger
	defer logger.Close()
	m.Run()
}
