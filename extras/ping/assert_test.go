package ping

import "testing"

func Test_assert(t *testing.T) {
	t.Run("assert false raises", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("a false assert should raise")
				return
			}
		}()
		assert(false, "should panic")
	})
	t.Run("assert true does not raise", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("a true assert should not raise")
				return
			}
		}()
		assert(true, "should not panic")
	})
}
