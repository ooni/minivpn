package vpn

import "testing"

func TestDefaultLoggerDoesNotFail(t *testing.T) {
	logger := defaultLogger{}
	logger.Debug("foo")
	logger.Debugf("%s", "foo")
	logger.Info("foo")
	logger.Infof("%s", "foo")
	logger.Warn("foo")
	logger.Warnf("%s", "foo")
	logger.Error("foo")
	logger.Errorf("%s", "foo")
}
