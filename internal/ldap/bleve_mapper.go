package ldap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ps78674/goldap/message"
)

func (s *server) buildBleveQuery(f message.Filter) (string, error) {
	s.l.Trace("Building search expression", "type", fmt.Sprintf("%T", f), "filter", fmt.Sprintf("%#v", f))
	var err error
	var etmp string
	var expr []string
	switch f := f.(type) {
	case message.FilterEqualityMatch:
		etmp, err = mapToBleveStringQuery(string(f.AttributeDesc()), "=", string(f.AssertionValue()))
		expr = append(expr, etmp)
	case message.FilterOr:
		for _, subf := range f {
			s, err := s.buildBleveQuery(subf)
			if err != nil {
				return "", err
			}
			expr = append(expr, s)
		}
	case message.FilterPresent:
		etmp, err = mapToBleveStringQuery(string(f), "=", "*")
		expr = append(expr, etmp)
	default:
		s.l.Warn("Unsupported search filter", "filter", fmt.Sprintf("%#v", f))
		err = errors.New("unsupported search filter")
	}
	return strings.Join(expr, " "), err
}

func mapToBleveStringQuery(attr, op, val string) (string, error) {
	var predicate, operator string

	switch attr {
	case "uid":
		predicate = "ID"
	case "cn":
		predicate = "Name"
	default:
		return "", errors.New("search attribute is unsupported")
	}

	switch op {
	case "=":
		operator = ":"
	default:
		return "", errors.New("search comparison is unsupported")
	}

	return predicate + operator + val, nil
}
