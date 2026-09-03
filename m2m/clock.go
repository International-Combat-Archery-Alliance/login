package m2m

import "time"

// Clock abstracts time so policies stay testable without threading now
// through every signature.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock returns the production clock.
func SystemClock() Clock { return systemClock{} }

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

// FixedClock returns a clock pinned at t (tests).
func FixedClock(t time.Time) Clock { return fixedClock{t: t} }
