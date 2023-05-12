// Package service contains code to manage services.
package service

import (
	"errors"
	"sync"
)

// ErrShutdown is the error returned by a service that is shutting down.
var ErrShutdown = errors.New("service is shutting down")

// Manager coordinates the lifeycles of the services implementing the OpenVPN
// protocol. The zero value is invalid; use [NewServiceManager].
type Manager struct {
	// shouldShutdown is closed to signal all workers to shut down.
	shouldShutdown chan any

	// shutdownOnce ensures we close shutdownSignal once.
	shutdownOnce sync.Once

	// wg tracks the running workers.
	wg *sync.WaitGroup
}

// StartWorker starts a worker in a background goroutine.
func (m *Manager) StartWorker(fx func()) {
	m.wg.Add(1)
	go fx()
}

// OnWorkerDone must be called when a worker goroutine terminates.
func (m *Manager) OnWorkerDone() {
	m.wg.Done()
}

// StartShutdown initiates the shutdown of all workers.
func (m *Manager) StartShutdown() {
	m.shutdownOnce.Do(func() {
		close(m.shouldShutdown)
	})
}

// ShouldShutdown returns the channel closed when workers should shut down.
func (m *Manager) ShouldShutdown() <-chan any {
	return m.shouldShutdown
}

// WaitWorkersShutdown blocks until all workers have shut down.
func (m *Manager) WaitWorkersShutdown() {
	m.wg.Wait()
}
