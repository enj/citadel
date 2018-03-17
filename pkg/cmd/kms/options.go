package kms

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"time"
)

const (
	// unix domain socket is the only supported protocol
	unixProtocol = "unix"

	minTimeout = time.Minute
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
	flag.StringVar(&args.endpoint, "endpoint", "", `the address to listen on, for example "unix:///var/run/kms-provider.sock"`)
	flag.StringVar(&args.command, "command", "", "the command to retrieve the key encryption key")
	flag.DurationVar(&args.timeout, "timeout", time.Hour, "maximum time in between failed calls to command before local key encryption key is zerod")
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
	endpoint, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen(unixProtocol, endpoint)
	if err != nil {
		return nil, err
	}

	return listener, nil
}

func parseEndpoint(endpoint string) (string, error) {
	if len(endpoint) == 0 {
		return "", fmt.Errorf("endpoint is required")
	}

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
