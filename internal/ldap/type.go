package ldap

import (
	"context"

	"github.com/hashicorp/go-hclog"
	ldap "github.com/ps78674/ldapserver"
)

type naClient interface {
	AuthEntity(context.Context, string, string) error
}

type server struct {
	*ldap.Server

	c naClient
	l hclog.Logger
}
