package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewVaultRoles(t *testing.T) {

	t.Run("when config map contains invalid role then only the valid one is returned", func(t *testing.T) {
		configMapData := map[string]string{
			"default":      `{"bound_service_account_names": ["default", "vault-agent-injector"], "bound_service_account_namespaces": ["kube-system", "default"], "token_policies": ["test"]}`,
			"invalid-role": `{"bound_service_account_names": ["*"], "bound_service_account_namespaces": ["*"], "token_policies": ["test"]}`,
		}

		vaultRoles := newVaultRoles(configMapData)
		assert.Equal(t, 1, len(vaultRoles))
	})
}

func TestVaultRoles_GetServiceAccountsSetByNamespace(t *testing.T) {

	configMapData := map[string]string{
		"default":   `{"bound_service_account_names": ["default", "vault-agent-injector"], "bound_service_account_namespaces": ["kube-system", "default"], "token_policies": ["test"]}`,
		"test-role": `{"bound_service_account_names": ["test", "default"], "bound_service_account_namespaces": ["test", "default"], "token_policies": ["test"]}`,
	}
	expcted := map[string]map[string]struct{}{
		"kube-system": {"default": {}, "vault-agent-injector": {}},
		"default":     {"default": {}, "vault-agent-injector": {}, "test": {}},
		"test":        {"default": {}, "test": {}},
	}

	actual := newVaultRoles(configMapData).getServiceAccountsSetByNamespace()
	assert.Equal(t, expcted, actual)
}
