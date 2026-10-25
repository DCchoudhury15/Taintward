//go:build race

package taintpolicy

// sync.Pool drops items under the race detector, so allocation counts are
// not meaningful there.
const raceEnabled = true
