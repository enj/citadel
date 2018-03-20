package kms

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"time"
	"os"
)

const (
	// unix domain socket is the only supported protocol
	unixProtocol = "unix"

	minTimeout = time.Minute

	fdStart = 3
)

type arguments struct {
	endpoint string
	command  string
	timeout  time.Duration
}

type options struct {
	listener net.Listener
	command  string
	timeout  time.Duration
}

var args = &arguments{}

func init() {
	flag.StringVar(&args.endpoint, "endpoint", "", `the listen address (ex. unix:///tmp/kms.sock)`)
	flag.StringVar(&args.command, "command", "", "the command to retrieve the key encryption key")
	flag.DurationVar(&args.timeout, "timeout", time.Hour, "maximum time to cache KEK locally")
	flag.Parse()
}

func getOptions() (*options, error) {
	listener, err := getListener(args.endpoint)
	if err != nil {
		return nil, err
	}

	if len(args.command) == 0 {
		return nil, fmt.Errorf("command is required")
	}

	if args.timeout < minTimeout {
		return nil, fmt.Errorf("the minimum supported timeout is %s", minTimeout)
	}

	return &options{
		listener: listener,
		command:  args.command,
		timeout:  args.timeout,
	}, nil
}

func getListener(endpoint string) (net.Listener, error) {
	if len(args.endpoint) == 0 {
		return getSocketActivationListener()
	}

	endpoint, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	return net.Listen(unixProtocol, endpoint)
}

func getSocketActivationListener() (net.Listener, error) {
	nsockets, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		return nil, fmt.Errorf("not running in a socket activation environment")
	}

	if nsockets != "1" {
		return nil, fmt.Errorf("multiple sockets are not supported")
	}

	file := os.NewFile(fdStart, "socket")
	if file == nil {
		return nil, fmt.Errorf("unable to create file from descriptor")
	}

	return net.FileListener(file)
}

func parseEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %v", endpoint, err)
	}

	if u.Scheme != unixProtocol {
		return "", fmt.Errorf("unsupported scheme %q, must be %q", u.Scheme, unixProtocol)
	}

	if len(u.Path) == 0 {
		return "", fmt.Errorf("endpoint path cannot be empty")
	}

	return u.Path, nil
}
