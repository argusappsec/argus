package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/argusappsec/argus/pkg/channel/uds"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/daemon"
)

// clientSession is a connected CLI client plus the lifecycle of whatever is
// serving it: nothing extra when a daemon was already listening, or the
// whole in-process daemon stack when we had to spawn one.
type clientSession struct {
	Client    *uds.Client
	Home      string
	InProcess bool

	cleanup func()
}

// Close tears down the client and, for the in-process fallback, shuts the
// embedded daemon down gracefully (waiting for memory curation).
func (cs *clientSession) Close() {
	if cs.cleanup != nil {
		cs.cleanup()
	}
}

// connectOrSpawn implements the client side of the daemon contract: the TUI
// is ALWAYS a UDS client. If the configured socket has a live daemon, we
// connect to it; otherwise we start the daemon stack inside this process on
// a private socket and connect to that. Either way the dispatch path is the
// same: auth → SessionManager → agent.
func connectOrSpawn(homeOverride string, hello uds.HelloOptions) (*clientSession, error) {
	home, err := resolveHome(homeOverride)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
	if err != nil {
		return nil, err
	}

	// A rejection means a live daemon answered: surface its reason instead
	// of silently spawning a second daemon next to it.
	socket := cfg.Daemon.SocketPath(home)
	c, dialErr := uds.Dial(socket, hello)
	if dialErr == nil {
		return &clientSession{Client: c, Home: home, cleanup: func() { c.Close() }}, nil
	}
	if _, rejected := dialErr.(*uds.ErrRejected); rejected {
		return nil, dialErr
	}

	// No daemon on the socket: in-process fallback on a private socket.
	dc, err := daemon.Build(home, cfg)
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "argus")
	if err != nil {
		dc.Close()
		return nil, fmt.Errorf("private socket dir: %w", err)
	}
	dc.SocketPath = filepath.Join(tmpDir, "s.sock")

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		daemon.RunChannels(runCtx, dc, uds.NewServer(dc))
		close(done)
	}()

	teardown := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		dc.Sessions.Drain(60 * time.Second) // let memory curation finish
		dc.Close()
		os.RemoveAll(tmpDir)
	}

	c, err = dialWithRetry(dc.SocketPath, hello, 3*time.Second)
	if err != nil {
		teardown()
		return nil, fmt.Errorf("embedded daemon: %w", err)
	}

	return &clientSession{
		Client:    c,
		Home:      home,
		InProcess: true,
		cleanup: func() {
			c.Close()
			// The server releases the Session when it sees the connection
			// drop; wait for that before draining so the curation for THIS
			// session is in the wait group.
			deadline := time.Now().Add(5 * time.Second)
			for dc.Sessions.Active() > 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			teardown()
		},
	}, nil
}

// dialWithRetry polls the socket until the embedded server is accepting.
func dialWithRetry(socket string, hello uds.HelloOptions, timeout time.Duration) (*uds.Client, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := uds.Dial(socket, hello)
		if err == nil {
			return c, nil
		}
		if _, rejected := err.(*uds.ErrRejected); rejected {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
