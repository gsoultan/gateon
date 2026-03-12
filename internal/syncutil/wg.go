package syncutil

import "sync"

// WaitGroup is a wrapper around sync.WaitGroup that provides a Go method.
type WaitGroup struct {
	sync.WaitGroup
}

// Go calls Add(1) and executes the function in a new goroutine.
// It calls Done() when the function returns.
func (wg *WaitGroup) Go(fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
}
