package ldap

import (
	"github.com/hashicorp/go-hclog"
)

// Option handle configuration of the underlying ldap.server type.
type Option func(*server)

// WithLogger sets the loggers for the server.
func WithLogger(l hclog.Logger) Option { return func(s *server) { s.l = l.Named("ldap") } }

// WithNetAuth sets the NetAuth client for the server.
func WithNetAuth(n naClient) Option { return func(s *server) { s.c = n } }
