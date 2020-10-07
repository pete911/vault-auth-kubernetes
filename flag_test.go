package main

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestDefaultFlagsFailValidation(t *testing.T) {

	_, err := ParseFlags()
	require.Error(t, err)
}

func TestFlags(t *testing.T) {

	args := []string{"vault-auth-kubernetes",
		"--kubeconfig", "/root/.kubeconfig",
		"--vault-host", "localhost:8443",
		"--vault-kube-host", "http://k8s:8443",
		"--vault-role-id", "abc",
		"--vault-secret-id", "def",
	}
	env := map[string]string{"VAK_VAULT_MOUNT": "backend"}

	rollback := setInput(args, env)
	defer func() { rollback() }()

	flags, err := ParseFlags()
	require.NoError(t, err)

	expected := Flags{
		Kubeconfig:    args[2],
		VaultMount:    env["VAK_VAULT_MOUNT"],
		VaultHost:     args[4],
		VaultKubeHost: args[6],
		VaultRoleId:   args[8],
		VaultSecretId: args[10],
	}
	assert.Equal(t, expected, flags)
}

func TestFlagsOverride(t *testing.T) {

	args := []string{"vault-auth-kubernetes",
		"--kubeconfig", "/root/.kubeconfig",
		"--vault-mount", "test/backend",
		"--vault-host", "localhost:8443",
		"--vault-kube-host", "http://k8s:8443",
		"--vault-role-id", "abc",
		"--vault-secret-id", "def",
	}
	env := map[string]string{"VAK_CLUSTER_NAME": "backend", "VAK_VAULT_HOST": "vault.com:443", "VAK_VAULT_KUBE_HOST": "test.com"}

	rollback := setInput(args, env)
	defer func() { rollback() }()

	flags, err := ParseFlags()
	require.NoError(t, err)

	expected := Flags{
		Kubeconfig:    args[2],
		VaultMount:    args[4],
		VaultHost:     args[6],
		VaultKubeHost: args[8],
		VaultRoleId:   args[10],
		VaultSecretId: args[12],
	}
	assert.Equal(t, expected, flags)
}

func TestFlagsValidateMissingVaultFlags(t *testing.T) {

	args := []string{"vault-auth-kubernetes",
		"--kubeconfig", "/root/.kubeconfig",
	}
	rollback := setInput(args, nil)
	defer func() { rollback() }()

	_, err := ParseFlags()
	require.Error(t, err)
}

// --- helper functions ---

func setInput(args []string, env map[string]string) (rollback func()) {

	osArgs := os.Args
	rollback = func() {
		os.Args = osArgs
		for k := range env {
			os.Unsetenv(k)
		}
	}

	os.Args = args
	for k, v := range env {
		os.Setenv(k, v)
	}
	return rollback
}
