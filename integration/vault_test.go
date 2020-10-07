// +build vault

package integration

import (
	"github.com/pete911/vault-auth-kubernetes/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

var (
	VaultHost     = getStringEnv("VAK_VAULT_HOST", "http://localhost:8200")
	VaultRoleId   = getStringEnv("VAK_VAULT_ROLE_ID", "3ff484bd-4062-3580-4b53-383974f829e5")
	VaultSecretId = getStringEnv("VAK_VAULT_SECRET_ID", "22c56ae6-0952-8084-e325-5fa8678291a5")

	testMount = "kubernetes/test-account/test-cluster"
	testJWT   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.zTWqeQdfDM0WKGBFig2-VmUpTLkIQ4DvAJN6_LzDZzU"
)

func getVaultConfig() vault.Config {

	return vault.Config{
		HttpClient: &http.Client{Timeout: 10 * time.Second},
		Host:       VaultHost,
		RoleId:     VaultRoleId,
		SecretId:   VaultSecretId,
	}
}

func TestVault(t *testing.T) {

	c, err := vault.NewClient(getVaultConfig(), testMount)
	require.NoError(t, err)

	t.Run("when auth kubernetes role is created then it can be listed", func(t *testing.T) {

		defer c.DeleteAuthKubernetes()
		err = c.InitAuthKubernetes("localhost", []byte("--- some ca ---"), []byte(testJWT))
		require.NoError(t, err)

		createRole(t, c, "test-role")

		assert.Equal(t, []string{"test-role"}, listRoles(t, c))
	})

	t.Run("when auth kubernetes role is deleted then it is not in the list", func(t *testing.T) {

		defer c.DeleteAuthKubernetes()
		err = c.InitAuthKubernetes("localhost", []byte("--- some ca ---"), []byte(testJWT))
		require.NoError(t, err)

		createRole(t, c, "test-role-1")
		createRole(t, c, "test-role-2")
		createRole(t, c, "test-role-3")

		deleteRole(t, c, "test-role-2")

		assert.Equal(t, []string{"test-role-1", "test-role-3"}, listRoles(t, c))
	})
}

// --- helper functions ---

func createRole(t *testing.T, c *vault.Client, roleName string) {
	require.NoError(t, c.CreateRole(roleName, testRole))
}

func deleteRole(t *testing.T, c *vault.Client, roleName string) {
	require.NoError(t, c.DeleteRole(roleName))
}

func listRoles(t *testing.T, c *vault.Client) []string {

	roles, err := c.ListRoles()
	require.NoError(t, err)
	return roles
}

// --- test data ---

var testRole = vault.Role{
	BoundServiceAccountNames:      []string{"vault-token-injector"},
	BoundServiceAccountNamespaces: []string{"default"},
	TokenPolicies:                 []string{"default"},
	TokenTTL:                      3600,
}
