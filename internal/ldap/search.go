package ldap

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ps78674/goldap/message"
	ldap "github.com/ps78674/ldapserver"

	"github.com/netauth/ldap/internal/buildinfo"

	pb "github.com/netauth/protocol"
)

func (s *server) handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	nc := strings.Join(s.nc, ", ")

	e := ldap.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "NetAuth")
	e.AddAttribute("vendorVersion", message.AttributeValue(buildinfo.Version))
	e.AddAttribute("objectClass", "top", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("namingContexts", message.AttributeValue(nc))
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func (s *server) handleSearchEntities(w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()
	s.l.Debug("Search Entities")

	r := m.GetSearchRequest()

	// This switch performs stage one of mapping from an ldap
	// search expression to a NetAuth search expression.  The
	// second phase of the mapping happens in another function.
	var expr string
	var err error
	switch r.Filter().(type) {
	case message.FilterEqualityMatch:
		f := r.Filter().(message.FilterEqualityMatch)
		expr, err = entitySearchExprHelper(string(f.AttributeDesc()), "=", string(f.AssertionValue()))
	default:
		s.l.Warn("Unsupported entity search filter", "type", fmt.Sprintf("%T", r.Filter()))
		s.l.Debug("Unsupported search filter", "filter", r.FilterString())
		err = errors.New("unsupported filter type")
	}
	if err != nil {
		// If err is non-nil at this point it must mean that
		// the above match didn't find a supported filter.
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Filter type not supported")
		w.Write(res)
		return
	}

	s.l.Debug("Searching entities", "query", expr)

	ents, err := s.c.EntitySearch(ctx, expr)
	if err != nil {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		res.SetDiagnosticMessage(err.Error())
		w.Write(res)
		return
	}

	for i := range ents {
		e, err := s.entitySearchResult(ctx, ents[i], r.BaseObject(), r.Attributes())
		if err != nil {
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)
			return
		}
		w.Write(e)
	}

	s.l.Debug("Entities", "res", ents)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// entitySearchResult maps an entity onto a SearchResultEntry,
// performing the additional lookup for groups to populate the
// memberOf attribute.  Though not implemented, the attrs list is
// plumbed down to this level to permit attribute filtering in the
// future.
func (s *server) entitySearchResult(ctx context.Context, e *pb.Entity, dn message.LDAPDN, attrs message.AttributeSelection) (message.SearchResultEntry, error) {
	res := ldap.NewSearchResultEntry("uid=" + e.GetID() + "," + string(dn))
	res.AddAttribute("uid", message.AttributeValue(e.GetID()))
	res.AddAttribute("uidNumber", message.AttributeValue(strconv.Itoa(int(e.GetNumber()))))

	grps, err := s.c.EntityGroups(ctx, e.GetID())
	if err != nil {
		return res, err
	}

	for i := range grps {
		g := "cn=" + grps[i].GetName() + ",ou=groups," + strings.Join(s.nc, ",")
		res.AddAttribute("memberOf", message.AttributeValue(g))
	}

	return res, nil
}

// entitySearchExprHelper helps in mapping ldap search expressions to
// search expressions that NetAuth understands.
func entitySearchExprHelper(attr, op, val string) (string, error) {
	var predicate, operator string

	switch attr {
	case "uid":
		predicate = "ID"
	default:
		return "", errors.New("search attribute is unsupported")
	}

	switch op {
	case "=":
		operator = ":"
		val = strconv.Quote(val)
	default:
		return "", errors.New("search comparison is unsupported")
	}

	return predicate + operator + val, nil
}

func (s *server) handleSearchGroups(w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()
	s.l.Debug("Search Groups")

	r := m.GetSearchRequest()

	// This switch performs stage one of mapping from an ldap
	// search expression to a NetAuth search expression.  The
	// second phase of the mapping happens in another function.
	var expr string
	var err error
	switch r.Filter().(type) {
	case message.FilterEqualityMatch:
		f := r.Filter().(message.FilterEqualityMatch)
		expr, err = groupSearchExprHelper(string(f.AttributeDesc()), "=", string(f.AssertionValue()))
	default:
		s.l.Warn("Unsupported group search filter", "type", fmt.Sprintf("%T", r.Filter()))
		s.l.Debug("Unsupported search filter", "filter", r.FilterString())
		err = errors.New("unsupported filter type")
	}
	if err != nil {
		// If err is non-nil at this point it must mean that
		// the above match didn't find a supported filter.
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Filter type not supported")
		w.Write(res)
		return
	}

	s.l.Debug("Searching groups", "expr", expr)

	groups, err := s.c.GroupSearch(ctx, expr)
	if err != nil {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		res.SetDiagnosticMessage(err.Error())
		w.Write(res)
		return
	}

	for i := range groups {
		s.l.Debug("Found group", "group", groups[i].GetName())
		e, err := s.groupSearchResult(ctx, groups[i], r.BaseObject(), r.Attributes())
		if err != nil {
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)
			return
		}
		w.Write(e)
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// groupSearchResult maps a group onto a SearchResultEntry, performing
// the additional lookup for groups to populate the member attribute.
// Though not implemented, the attrs list is plumbed down to this
// level to permit attribute filtering in the future.
func (s *server) groupSearchResult(ctx context.Context, g *pb.Group, dn message.LDAPDN, attrs message.AttributeSelection) (message.SearchResultEntry, error) {
	res := ldap.NewSearchResultEntry("cn=" + g.GetName() + "," + string(dn))
	res.AddAttribute("cn", message.AttributeValue(g.GetName()))
	res.AddAttribute("gidNumber", message.AttributeValue(strconv.Itoa(int(g.GetNumber()))))

	members, err := s.c.GroupMembers(ctx, g.GetName())
	if err != nil {
		return res, err
	}

	for i := range members {
		g := "uid=" + members[i].GetID() + ",ou=entities," + strings.Join(s.nc, ",")
		res.AddAttribute("member", message.AttributeValue(g))
	}

	return res, nil
}

// groupSearchExprHelper helps in mapping ldap search expressions to
// search expressions that NetAuth understands.
func groupSearchExprHelper(attr, op, val string) (string, error) {
	var predicate, operator string

	switch attr {
	case "cn":
		predicate = "Name"
	default:
		return "", errors.New("search attribute is unsupported")
	}

	switch op {
	case "=":
		operator = ":"
		val = strconv.Quote(val)
	default:
		return "", errors.New("search comparison is unsupported")
	}

	return predicate + operator + val, nil
}
