package ldap

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
	ldap "github.com/ps78674/ldapserver"
)

// New returns a new ldap server instance
func New(l hclog.Logger, nacl naClient) *server {
	x := new(server)
	x.l = l.Named("ldap")
	x.c = nacl
	x.Server = ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.NotFound(x.handleNotFound)
	routes.Abandon(x.handleAbandon)
	routes.Bind(x.handleBind)

	routes.Search(x.handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")

	routes.Search(x.handleSearchMyCompany).
		BaseDn("o=My Company, c=US").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Compagny Root")

	routes.Search(x.handleSearch).Label("Search - Generic")

	x.Handle(routes)

	return x
}

// Serve serves a plaintext DSA on the provided bind string.
func (s *server) Serve(bind string) error {
	chErr := make(chan error)
	defer close(chErr)
	go s.ListenAndServe(bind, chErr)
	if err := <-chErr; err != nil {
		s.l.Error("Error from main server thread", "error", err)
		return err
	}

	ch := make(chan os.Signal, 5)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	s.Stop()
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
