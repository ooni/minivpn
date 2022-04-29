// Package memoryless helps repeated calls to a function be distributed across
// time in a memoryless fashion.
// Vendored from https://github.com/m-lab/go/blob/master/memoryless/memoryless.go

// SPDX-License-Identifier: Apache-2.0
// (c) Peter Boothe

package memoryless

import (
	"fmt"
	"log"
	"math/rand"
	"time"
)

type Config struct {
	// Expected records the expected/mean/average amount of time between runs.
	Expected time.Duration
	// Min provides clamping of the randomly produced value. All timers will wait
	// at least Min time.
	Min time.Duration
	// Max provides clamping of the randomly produced value. All timers will take
	// at most Max time.
	Max time.Duration

	// Once is provided as a helper, because frequently for unit testing and
	// integration testing, you only want the "Forever" loop to run once.
	//
	// The zero value of this struct has Once set to false, which means the value
	// only needs to be set explicitly in codepaths where it might be true.
	Once bool
}

func (c Config) waittime() time.Duration {
	wt := time.Duration(rand.ExpFloat64() * float64(c.Expected))
	if wt < c.Min {
		wt = c.Min
	}
	if c.Max != 0 && wt > c.Max {
		wt = c.Max
	}
	log.Println("wait time:", wt)
	return wt
}

// Check whether the config contrains sensible values. It return an error if the
// config makes no mathematical sense, and nil if everything is okay.
func (c Config) Check() error {
	if !(0 <= c.Min && c.Min <= c.Expected && (c.Max == 0 || c.Expected <= c.Max)) {
		return fmt.Errorf(
			"The arguments to Run make no sense. It should be true that Min <= Expected <= Max (or Min <= Expected and Max is 0), "+
				"but that is not true for Min(%v) Expected(%v) Max(%v).",
			c.Min, c.Expected, c.Max)
	}
	return nil
}

// newTimer constructs and returns a timer. This function assumes that the
// config has no errors.
func newTimer(c Config) *time.Timer {
	return time.NewTimer(c.waittime())
}

// NewTimer constructs a single-shot time.Timer that, if repeatedly used to
// construct a series of timers, will ensure that the resulting events conform
// to the memoryless distribution. For more on how this could and should be
// used, see the comments to Ticker. It is intended to be a drop-in replacement
// for time.NewTimer.
func NewTimer(c Config) (*time.Timer, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	return newTimer(c), nil
}
