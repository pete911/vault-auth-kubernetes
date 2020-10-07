package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/pkg/util"
	"reflect"
	"sort"
)

// https://www.vaultproject.io/api-docs/auth/kubernetes#create-role
type Role struct {
	BoundServiceAccountNames      []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	TokenPolicies                 []string `json:"token_policies"`
	TokenTTL                      int      `json:"token_ttl"`
	// TODO add more fields, add omit empty tag
}

func NewRole(rawRole []byte) (Role, error) {

	var role Role
	if err := json.Unmarshal(rawRole, &role); err != nil {
		return Role{}, fmt.Errorf("unmarshal vault role: %v", err)
	}

	role = role.sanitize()
	if err := role.validate(); err != nil {
		return Role{}, err
	}
	return role, nil
}

func (r Role) sanitize() Role {

	// remove duplicates if any
	r.BoundServiceAccountNamespaces = util.StringSliceToSet(r.BoundServiceAccountNamespaces)
	r.BoundServiceAccountNames = util.StringSliceToSet(r.BoundServiceAccountNames)

	// no need to keep other values if we find wildcard
	if util.StringSliceContains(r.BoundServiceAccountNamespaces, "*") {
		r.BoundServiceAccountNamespaces = []string{"*"}
	}
	if util.StringSliceContains(r.BoundServiceAccountNames, "*") {
		r.BoundServiceAccountNames = []string{"*"}
	}
	return r
}

func (r Role) validate() error {

	if util.StringSliceContains(r.BoundServiceAccountNamespaces, "*") &&
		util.StringSliceContains(r.BoundServiceAccountNames, "*") {
		return errors.New("vault role cannot contain * in both bound service account namespaces and names")
	}
	return nil
}

func (r Role) Equal(r2 Role) bool {

	sort.Sort(sort.StringSlice(r.BoundServiceAccountNames))
	sort.Sort(sort.StringSlice(r.BoundServiceAccountNamespaces))
	sort.Sort(sort.StringSlice(r.TokenPolicies))

	sort.Sort(sort.StringSlice(r2.BoundServiceAccountNames))
	sort.Sort(sort.StringSlice(r2.BoundServiceAccountNamespaces))
	sort.Sort(sort.StringSlice(r2.TokenPolicies))

	return reflect.DeepEqual(r, r2)
}
