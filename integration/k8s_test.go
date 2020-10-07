// +build k8s

package integration

import (
	"github.com/pete911/vault-auth-kubernetes/pkg/k8s"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var kubeconfigPath = getStringEnv("KUBECONFIG", "")

func TestK8s(t *testing.T) {

	kubeconfig, err := k8s.LoadKubeconfig(kubeconfigPath)
	require.NoError(t, err)
	c := k8s.NewClient(kubeconfig.Clientset)

	t.Run("when get namespaces then list of namespaces names is returned", func(t *testing.T) {
		assert.NotEqual(t, 0, len(getNamespaces(t, c)))
	})

	t.Run("when I get service account token on newly created service account then token is returned", func(t *testing.T) {

		defer deleteServiceAccount(t, c, "default", "test-account")

		token := createAndGetServiceAccountToken(t, c, "default", "test-account")
		assert.NotEmpty(t, token)
	})
}

// --- helper functions ---

func getNamespaces(t *testing.T, c k8s.Client) []string {

	namespaces, err := c.GetNamespaces()
	require.NoError(t, err)
	return namespaces
}

func createAndGetServiceAccountToken(t *testing.T, c k8s.Client, namespace, name string) []byte {

	require.NoError(t, c.CreateServiceAccount(namespace, name, nil))
	token, err := c.GetServiceAccountToken(namespace, name)
	require.NoError(t, err)
	return token
}

func deleteServiceAccount(t *testing.T, c k8s.Client, namespace, name string) {
	require.NoError(t, c.DeleteServiceAccount(namespace, name))
}
