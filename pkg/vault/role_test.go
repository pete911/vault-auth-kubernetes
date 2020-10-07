package vault

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewRole(t *testing.T) {

	t.Run("when role has duplicate namespaces and service accounts then the duplicates are removed", func(t *testing.T) {

		rawRole := []byte(`{"bound_service_account_names": ["default", "vault-agent-injector", "default"], "bound_service_account_namespaces": ["kube-system", "kube-system", "default"], "token_policies": ["test"]}`)
		role, err := NewRole(rawRole)

		require.NoError(t, err)
		require.Equal(t, 2, len(role.BoundServiceAccountNames))
		assert.Equal(t, "default", role.BoundServiceAccountNames[0])
		assert.Equal(t, "vault-agent-injector", role.BoundServiceAccountNames[1])
		require.Equal(t, 2, len(role.BoundServiceAccountNamespaces))
		assert.Equal(t, "kube-system", role.BoundServiceAccountNamespaces[0])
		assert.Equal(t, "default", role.BoundServiceAccountNamespaces[1])
	})

	t.Run("when role has wildcard in namespaces then other namespaces are removed", func(t *testing.T) {

		rawRole := []byte(`{"bound_service_account_names": ["default"], "bound_service_account_namespaces": ["kube-system", "default", "*"], "token_policies": ["test"]}`)
		role, err := NewRole(rawRole)

		require.NoError(t, err)
		require.Equal(t, 1, len(role.BoundServiceAccountNames))
		assert.Equal(t, "default", role.BoundServiceAccountNames[0])
		require.Equal(t, 1, len(role.BoundServiceAccountNamespaces))
		assert.Equal(t, "*", role.BoundServiceAccountNamespaces[0])
	})

	t.Run("when role has wildcard in service accounts then other service accounts are removed", func(t *testing.T) {

		rawRole := []byte(`{"bound_service_account_names": ["default", "vault-agent-injector", "*"], "bound_service_account_namespaces": ["kube-system"], "token_policies": ["test"]}`)
		role, err := NewRole(rawRole)

		require.NoError(t, err)
		require.Equal(t, 1, len(role.BoundServiceAccountNames))
		assert.Equal(t, "*", role.BoundServiceAccountNames[0])
		require.Equal(t, 1, len(role.BoundServiceAccountNamespaces))
		assert.Equal(t, "kube-system", role.BoundServiceAccountNamespaces[0])
	})

	t.Run("when role has wildcard in service accounts and namespaces then validation error is returned", func(t *testing.T) {

		rawRole := []byte(`{"bound_service_account_names": ["default", "*"], "bound_service_account_namespaces": ["*"], "token_policies": ["test"]}`)
		_, err := NewRole(rawRole)

		require.Error(t, err)
	})

	t.Run("when raw role is in invalid json then error is returned", func(t *testing.T) {

		rawRole := []byte(` - role: invalid json`)
		_, err := NewRole(rawRole)

		require.Error(t, err)
	})
}

func TestRole_Equal(t *testing.T) {

	t.Run("when two roles have different fields then they are not equal", func(t *testing.T) {

		r1 := Role{
			BoundServiceAccountNames:      []string{"default"},
			BoundServiceAccountNamespaces: []string{"test1"},
			TokenPolicies:                 []string{"test1"},
			TokenTTL:                      3600,
		}

		r2 := Role{
			BoundServiceAccountNames:      []string{"vault-injector"},
			BoundServiceAccountNamespaces: []string{"test2", "kube-system"},
			TokenPolicies:                 []string{"test2"},
			TokenTTL:                      1800,
		}

		assert.False(t, r1.Equal(r2))
	})

	t.Run("when two roles have same fields then they are equal", func(t *testing.T) {

		r1 := Role{
			BoundServiceAccountNames:      []string{"vault-injector"},
			BoundServiceAccountNamespaces: []string{"test", "kube-system"},
			TokenPolicies:                 []string{"test"},
			TokenTTL:                      1800,
		}

		r2 := Role{
			BoundServiceAccountNames:      []string{"vault-injector"},
			BoundServiceAccountNamespaces: []string{"test", "kube-system"},
			TokenPolicies:                 []string{"test"},
			TokenTTL:                      1800,
		}

		assert.True(t, r1.Equal(r2))
	})

	t.Run("when two roles have same slice fields but in different order then they are equal", func(t *testing.T) {

		r1 := Role{
			BoundServiceAccountNames:      []string{"default", "vault-injector"},
			BoundServiceAccountNamespaces: []string{"kube-system", "test"},
			TokenPolicies:                 []string{"test", "default"},
			TokenTTL:                      1800,
		}

		r2 := Role{
			BoundServiceAccountNames:      []string{"vault-injector", "default"},
			BoundServiceAccountNamespaces: []string{"test", "kube-system"},
			TokenPolicies:                 []string{"default", "test"},
			TokenTTL:                      1800,
		}

		assert.True(t, r1.Equal(r2))
	})
}
