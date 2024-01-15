package optional

import (
	"reflect"

	"github.com/ooni/minivpn/internal/runtimex"
)

// Value is an optional value. The zero value of this structure
// is equivalent to the one you get when calling [None].
type Value[T any] struct {
	// indirect is the indirect pointer to the value.
	indirect *T
}

// None constructs an empty value.
func None[T any]() Value[T] {
	return Value[T]{nil}
}

// Some constructs a some value unless T is a pointer and points to
// nil, in which case [Some] is equivalent to [None].
func Some[T any](value T) Value[T] {
	v := Value[T]{}
	maybeSetFromValue(&v, value)
	return v
}

// maybeSetFromValue sets the underlying value unless T is a pointer
// and points to nil in which case we set the Value to be empty.
func maybeSetFromValue[T any](v *Value[T], value T) {
	rv := reflect.ValueOf(value)
	if rv.Type().Kind() == reflect.Pointer && rv.IsNil() {
		v.indirect = nil
		return
	}
	v.indirect = &value
}

// IsNone returns whether this [Value] is empty.
func (v Value[T]) IsNone() bool {
	return v.indirect == nil
}

// Unwrap returns the underlying value or panics. In case of
// panic, the value passed to panic is an error.
func (v Value[T]) Unwrap() T {
	runtimex.Assert(!v.IsNone(), "is none")
	return *v.indirect
}

// UnwrapOr returns the fallback if the [Value] is empty.
func (v Value[T]) UnwrapOr(fallback T) T {
	if v.IsNone() {
		return fallback
	}
	return v.Unwrap()
}
