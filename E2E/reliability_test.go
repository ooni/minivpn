package reliability_test

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestLoss(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
	})
}
