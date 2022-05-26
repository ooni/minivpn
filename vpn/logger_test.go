package vpn

import (
	"os"
	"testing"
)

func TestDefaultLoggerDoesNotFail(t *testing.T) {
	os.Setenv("EXTRA_DEBUG", "1")
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
