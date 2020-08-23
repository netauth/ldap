package ldap

import (
	"context"

	ldap "github.com/ps78674/ldapserver"
)

func (s *server) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()

	r := m.GetBindRequest()
	// The server only supports simple auth, no SASL or anything
	// fancy because we are after all just fronting another
	// protocol.
	if r.AuthenticationChoice() != "simple" {
		res := ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
		w.Write(res)
		return
	}

	s.l.Debug("Bind from dn", "dn", r.Name())

	entityID, err := s.entityIDFromDN(r.Name())
	if err != nil {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(err.Error())
		s.l.Warn("Request with invalid DN", "dn", r.Name())
		w.Write(res)
		return
	}

	if err := s.c.AuthEntity(ctx, entityID, string(r.AuthenticationSimple())); err != nil {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
		w.Write(res)
		return
	}

	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
