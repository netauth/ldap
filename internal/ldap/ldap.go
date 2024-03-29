package ldap

import (
	"strings"

	ldap "github.com/ps78674/ldapserver"
)

// New returns a new ldap server instance
func New(opts ...Option) *server {
	x := new(server)
	for _, o := range opts {
		o(x)
	}
	x.Server = ldap.NewServer()

	x.routes = ldap.NewRouteMux()
	x.routes.NotFound(x.handleNotFound)
	x.routes.Abandon(x.handleAbandon)
	x.routes.Bind(x.handleBind)

	x.routes.Search(x.handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")

	x.Handle(x.routes)

	return x
}

// Serve serves a plaintext DSA on the provided bind string.
func (s *server) Serve(bind string) error {
	chErr := make(chan error)
	go s.ListenAndServe(bind, chErr)
	if err := <-chErr; err != nil {
		s.l.Error("Error from main server thread", "error", err)
		return err
	}
	return nil
}

// ServeTLS serves a TLS encrypted DSA on the provided bindstring
// using a key/cert pair located at the paths provided.  Key and
// certificate should be PEM encoded.
func (s *server) ServeTLS(bind, keypath, certpath string) error {
	chErr := make(chan error)
	go s.ListenAndServeTLS(bind, certpath, keypath, chErr)
	if err := <-chErr; err != nil {
		s.l.Error("Error from main server thread", "error", err)
		return err
	}
	return nil
}

func (s *server) handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	switch r.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func (s *server) handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
	}
}

func (s *server) SetDomain(domain string) {
	nc := "dc=netauth,"
	parts := strings.Split(domain, ".")
	for i := range parts {
		nc += "dc=" + parts[i] + ","
	}
	nc = strings.TrimSuffix(nc, ",")

	s.nc = strings.Split(nc, ",")
	for i := range s.nc {
		s.nc[i] = strings.TrimSpace(s.nc[i])
	}

	// Register routes that are dependent on the namingConvention
	entitySearchDN := "ou=entities," + strings.Join(s.nc, ",")
	s.routes.Search(s.handleSearchEntities).
		BaseDn(entitySearchDN).
		Scope(ldap.SearchRequestHomeSubtree).
		Label("Search - Entities")

	groupSearchDN := "ou=groups," + strings.Join(s.nc, ",")
	s.routes.Search(s.handleSearchGroups).
		BaseDn(groupSearchDN).
		Scope(ldap.SearchRequestHomeSubtree).
		Label("Search - Entities")

}
