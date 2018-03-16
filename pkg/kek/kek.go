package kek

import (
	"bytes"
	"errors"
	"os/exec"
	"sync"
	"time"
)

type KeyEncryptionKeyService interface {
	Get() (kek []byte, err error)
	Stop()
}

func NewCommandKEKService(cmd string, duration time.Duration) (KeyEncryptionKeyService, error) {
	c := &cmdKEK{cmd: cmd, duration: duration, stop: make(chan struct{})}
	if err := c.prime(); err != nil {
		return nil, err
	}
	go c.run()
	return c, nil
}

var errEmptyKey = errors.New("empty key encryption key")

type cmdKEK struct {
	mutex sync.RWMutex
	stop  chan struct{}

	cmd      string
	duration time.Duration

	kek      []byte
	fetchErr error
}

func (c *cmdKEK) Get() ([]byte, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if len(c.kek) == 0 {
		return nil, c.fetchErr
	}

	return c.kek, nil
}

func (c *cmdKEK) Stop() {
	close(c.stop)
}

func (c *cmdKEK) setValidSate(kek []byte) {
	c.mutex.Lock()
	c.kek = kek
	c.fetchErr = nil
	c.mutex.Unlock()
}

func (c *cmdKEK) setErrorState(err error) {
	c.mutex.Lock()
	c.fetchErr = err
	c.kek = nil
	c.mutex.Unlock()
}

func (c *cmdKEK) getKey() ([]byte, error) {
	kek, err := exec.Command("sh", "-c", c.cmd).Output() // TODO pass env vars?
	if err != nil {
		return nil, err
	}
	if len(kek) == 0 {
		return nil, errEmptyKey
	}
	return kek, nil
}

func (c *cmdKEK) run() {
	const factor = 5 // TODO move constant, maybe make configurable?
	ticker := time.NewTicker(c.duration / factor)
	defer ticker.Stop()

	current := 0

	for {
		select {
		case <-c.stop:
			return

		case <-ticker.C:
			kek, err := c.getKey()
			if err != nil {
				current++
				if current >= factor {
					c.setErrorState(err)
				}
				continue
			}
			if !bytes.Equal(kek, c.kek) {
				c.setValidSate(kek)
			}
			current = 0
		}
	}
}

func (c *cmdKEK) prime() error {
	kek, err := c.getKey()
	if err != nil {
		return err
	}
	c.kek = kek
	return nil
}
