package ldap

import (
	"context"
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
	expr, err := s.buildBleveQuery(r.Filter())
	if err != nil {
		// If err is non-nil at this point it must mean that
		// the above match didn't find a supported filter.
		s.l.Warn("Unsupported Search Filter, this is a bug, please file a report", "filter", r.Filter())
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

	memberOf := []message.AttributeValue{}
	for i := range grps {
		g := "cn=" + grps[i].GetName() + ",ou=groups," + strings.Join(s.nc, ",")
		memberOf = append(memberOf, message.AttributeValue(g))
	}
	res.AddAttribute("memberOf", memberOf...)

	return res, nil
}

func (s *server) handleSearchGroups(w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()
	s.l.Debug("Search Groups")

	r := m.GetSearchRequest()

	expr, err := s.buildBleveQuery(r.Filter())
	if err != nil {
		// If err is non-nil at this point it must mean that
		// the above match didn't find a supported filter.
		s.l.Warn("Unsupported Search Filter, this is a bug, please file a report", "filter", r.Filter())
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

	memberList := []message.AttributeValue{}
	for i := range members {
		g := "uid=" + members[i].GetID() + ",ou=entities," + strings.Join(s.nc, ",")
		memberList = append(memberList, message.AttributeValue(g))
	}
	res.AddAttribute("member", memberList...)

	return res, nil
}
