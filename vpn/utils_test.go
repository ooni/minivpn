package vpn

import "testing"

func Test_panicIfFalse(t *testing.T) {
	t.Run("panics when false", func(t *testing.T) {
		var happened bool
		func() {
			defer func() {
				happened = recover() != nil
			}()
			panicIfFalse(false, "should happen")
		}()
		if !happened {
			t.Fatal("did not panic")
		}
	})

	t.Run("does nothing when true", func(t *testing.T) {
		panicIfFalse(true, "should not happen")
	})
}
