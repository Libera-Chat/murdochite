package util

import "runtime"

// Stack returns a formatted stack trace of the goroutine that calls it.
// It calls runtime.Stack with a large enough buffer to capture the entire trace.
// This is a modified version of the stdlib debug.Stack. Original License belongs to the go developers.
func Stack() []byte {
	buf := make([]byte, 8192)

	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}

		buf = make([]byte, 2*len(buf))
	}
}
