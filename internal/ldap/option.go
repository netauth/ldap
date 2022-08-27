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

// WithAnonBind enables anonymous bind support which is necessary in
// some cases that the client wishes to do an initial anonymous bind,
// followed by an immediate rebind as a real entity.
func WithAnonBind(a bool) Option { return func(s *server) { s.allowAnon = a } }
