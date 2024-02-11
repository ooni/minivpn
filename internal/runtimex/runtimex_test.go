// Package runtimex contains [runtime] extensions.
package runtimex

import (
	"errors"
	"testing"
)

func TestPanicIfFalse(t *testing.T) {
	t.Run("expect a panic for a false statement", func(t *testing.T) {
		assertPanic(t, func() { PanicIfFalse(true == false, "should panic") })
	})
	t.Run("do not expect a panic for a true statement", func(t *testing.T) {
		PanicIfFalse(1 == 0+1, "should not panic")
	})
}

func TestPanicIfTrue(t *testing.T) {
	t.Run("expect a panic for a true statement", func(t *testing.T) {
		assertPanic(t, func() { PanicIfTrue(1 == 0+1, "should panic") })
	})
	t.Run("do not expect a panic for a false statement", func(t *testing.T) {
		PanicIfTrue(1 == 0, "should not panic")
	})
}

func TestAssert(t *testing.T) {
	t.Run("expect a panic for a false statement", func(t *testing.T) {
		assertPanic(t, func() { Assert(true == false, "should panic") })
	})
	t.Run("do not expect a panic for a true statement", func(t *testing.T) {
		Assert(1 == 0+1, "should not panic")
	})
}

func TestPanicOnError(t *testing.T) {
	t.Run("expect a panic for a non-null error", func(t *testing.T) {
		assertPanic(t, func() { PanicOnError(errors.New("bad thing"), "should panic") })
	})
	t.Run("do not expect a panic for a false statement", func(t *testing.T) {
		PanicOnError(nil, "should not panic")
	})
}

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected code to panic")
		}
	}()
	f()
}
