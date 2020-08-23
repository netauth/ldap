package ldap

import (
	"context"

	"github.com/hashicorp/go-hclog"
	ldap "github.com/ps78674/ldapserver"

	pb "github.com/netauth/protocol"
)

type naClient interface {
	AuthEntity(context.Context, string, string) error
	EntitySearch(context.Context, string) ([]*pb.Entity, error)
	EntityGroups(context.Context, string) ([]*pb.Group, error)
}

type server struct {
	*ldap.Server

	routes *ldap.RouteMux

	c naClient
	l hclog.Logger

	nc []string
}
