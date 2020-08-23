package ldap

import (
	"errors"
	"strings"

	"github.com/ps78674/goldap/message"
)

// entityIDFromDN parses out an ID from a given DN.  This only works
// for ID's that don't contain an escaped comma, but these aren't
// valid in NetAuth anyway, so this is taken as a known defect.
func (s *server) entityIDFromDN(dn message.LDAPDN) (string, error) {
	parts := strings.Split(string(dn), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	if !strings.HasPrefix(parts[0], "uid=") {
		return "", errors.New("entity DN must start with uid=")
	}

	if parts[1] != "cn=entities" {
		return "", errors.New("entity DN is underneath cn=entities")
	}

	for i, p := range parts[2:] {
		if p != s.nc[i] {
			return "", errors.New("queries must be rooted at " + strings.Join(s.nc, ","))
		}
	}

	return strings.TrimPrefix(parts[0], "uid="), nil
}
