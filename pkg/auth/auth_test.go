package auth

import (
	"errors"
	"github.com/pete911/vault-auth-kubernetes/pkg/vault"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

var testConfig = Config{
	VaultMount: "test-account/test-cluster",
	K8sHost:    "http://kube.host",
	K8sCA:      []byte("--- CA ---"),
}

func TestAuth_initTokenReviewer(t *testing.T) {

	token := []byte("test token")
	var emptyAnnotations map[string]string

	t.Run("when kube service account and vault auth requests are successful then no error is return", func(t *testing.T) {

		vaultClient := new(VaultClientMock)
		vaultClient.On("InitAuthKubernetes", testConfig.K8sHost, testConfig.K8sCA, token).Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("CreateServiceAccount", tokenReviewerNamespace, tokenReviewerServiceAccount, emptyAnnotations).Return(nil)
		k8sClient.On("GetServiceAccountToken", tokenReviewerNamespace, tokenReviewerServiceAccount).Return(token, nil)
		k8sClient.On("CreateAuthDelegatorClusterRoleBinding", tokenReviewerClusterRoleBinding, tokenReviewerNamespace, tokenReviewerServiceAccount).Return(nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		err := a.initTokenReviewer()
		require.NoError(t, err)
		vaultClient.AssertExpectations(t)
		k8sClient.AssertExpectations(t)
	})

	t.Run("when kube service account creation fails then error is return", func(t *testing.T) {

		k8sClient := new(K8sClientMock)
		k8sClient.On("CreateServiceAccount", tokenReviewerNamespace, tokenReviewerServiceAccount, emptyAnnotations).Return(errors.New("cannot create service account"))

		a := NewAuth(testConfig, nil, k8sClient)
		err := a.initTokenReviewer()
		require.Error(t, err)
		k8sClient.AssertExpectations(t)
	})

	t.Run("when get service account token fails then error is return", func(t *testing.T) {

		k8sClient := new(K8sClientMock)
		k8sClient.On("CreateServiceAccount", tokenReviewerNamespace, tokenReviewerServiceAccount, emptyAnnotations).Return(nil)
		k8sClient.On("GetServiceAccountToken", tokenReviewerNamespace, tokenReviewerServiceAccount).Return(nil, errors.New("cannot retrieve kube token"))

		a := NewAuth(testConfig, nil, k8sClient)
		err := a.initTokenReviewer()
		require.Error(t, err)
		k8sClient.AssertExpectations(t)
	})

	t.Run("when kube cluster role binding fails then error is return", func(t *testing.T) {

		k8sClient := new(K8sClientMock)
		k8sClient.On("CreateServiceAccount", tokenReviewerNamespace, tokenReviewerServiceAccount, emptyAnnotations).Return(nil)
		k8sClient.On("GetServiceAccountToken", tokenReviewerNamespace, tokenReviewerServiceAccount).Return(token, nil)
		k8sClient.On("CreateAuthDelegatorClusterRoleBinding", tokenReviewerClusterRoleBinding, tokenReviewerNamespace, tokenReviewerServiceAccount).Return(errors.New("cannot create binding"))

		a := NewAuth(testConfig, nil, k8sClient)
		err := a.initTokenReviewer()
		require.Error(t, err)
		k8sClient.AssertExpectations(t)
	})
}

func TestAuth_initServiceAccounts(t *testing.T) {

	t.Run("when vault auth kubernetes config map contains namespaces with vault-policies then vault roles and kube service accounts are updated", func(t *testing.T) {

		// vault roles and service accounts are re-created even if they already exists (to ensure that latest code changes are reflected)
		configMapData := map[string]string{
			"role1": `{"bound_service_account_names": ["vault-agent-injector", "default"], "bound_service_account_namespaces": ["kube-system", "default"], "token_policies": ["test"]}`,
			"role2": `{"bound_service_account_names": ["vault-agent-injector"], "bound_service_account_namespaces": ["kube-system"], "token_policies": ["test", "default"]}`,
		}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{"role1", "role3"}, nil)
		vaultClient.On("DeleteRole", "role3").Return(nil)
		vaultClient.On("CreateRole", "role1", mock.Anything).Return(nil)
		vaultClient.On("CreateRole", "role2", mock.Anything).Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system", "test", "default"}, nil)
		k8sClient.On("GetServiceAccounts", "test", serviceAccountAnnotations).Return([]string{"vault-agent-injector", "default"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("GetServiceAccounts", "default", serviceAccountAnnotations).Return(nil, nil)
		k8sClient.On("DeleteServiceAccount", "test", "vault-agent-injector").Return(nil)
		k8sClient.On("DeleteServiceAccount", "test", "default").Return(nil)
		k8sClient.On("CreateServiceAccount", "kube-system", "vault-agent-injector", serviceAccountAnnotations).Return(nil)
		k8sClient.On("CreateServiceAccount", "kube-system", "default", serviceAccountAnnotations).Return(nil)
		k8sClient.On("CreateServiceAccount", "default", "vault-agent-injector", serviceAccountAnnotations).Return(nil)
		k8sClient.On("CreateServiceAccount", "default", "default", serviceAccountAnnotations).Return(nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when vault auth kubernetes config fails then kube and vault are not updated", func(t *testing.T) {

		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).
			Return(nil, errors.New("get vault auth kubernetes config map request failed"))

		a := NewAuth(testConfig, nil, k8sClient)
		a.initServiceAccounts()
	})

	t.Run("when vault auth kubernetes config map does not contains namespaces with vault-policies then kube and vault is cleaned up", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{"role1"}, nil)
		vaultClient.On("DeleteRole", "role1").Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system", "default"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("GetServiceAccounts", "default", serviceAccountAnnotations).Return(nil, nil)
		k8sClient.On("DeleteServiceAccount", "kube-system", "vault-agent-injector").Return(nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when one service account deletion fails then flow does not stop and other service accounts are deleted", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{}, nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system", "default", "test"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("GetServiceAccounts", "default", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("GetServiceAccounts", "test", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("DeleteServiceAccount", "kube-system", "vault-agent-injector").Return(errors.New("failed to delete service account")).Once()
		k8sClient.On("DeleteServiceAccount", "default", "vault-agent-injector").Return(nil).Once()
		k8sClient.On("DeleteServiceAccount", "test", "vault-agent-injector").Return(nil).Once()

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when get delete service accounts fails in one namespace then flow does not stop and other namespace is tried", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{}, nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system", "default", "test"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{}, errors.New("test failure"))
		k8sClient.On("GetServiceAccounts", "default", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("GetServiceAccounts", "test", serviceAccountAnnotations).Return([]string{"vault-agent-injector"}, nil)
		k8sClient.On("DeleteServiceAccount", "default", "vault-agent-injector").Return(nil).Once()
		k8sClient.On("DeleteServiceAccount", "test", "vault-agent-injector").Return(nil).Once()

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when one service account not in vault config fails to delete then flow continues and other service accounts are deleted", func(t *testing.T) {

		configMapData := map[string]string{
			"role": `{"bound_service_account_names": ["default"], "bound_service_account_namespaces": ["kube-system"], "token_policies": ["test"]}`,
		}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{}, nil)
		vaultClient.On("CreateRole", "role", mock.Anything).Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{"default", "vault-agent-injector", "test"}, nil)
		k8sClient.On("CreateServiceAccount", "kube-system", "default", serviceAccountAnnotations).Return(nil).Once()
		k8sClient.On("DeleteServiceAccount", "kube-system", "vault-agent-injector").Return(errors.New("test failure")).Once()
		k8sClient.On("DeleteServiceAccount", "kube-system", "test").Return(nil).Once()

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when get namespaces request fails then no service accounts are deleted", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{}, nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return(nil, errors.New("failed to get namespaces"))

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when one service account creation fails then flow does not stop and other service accounts are created", func(t *testing.T) {

		configMapData := map[string]string{
			"role1": `{"bound_service_account_names": ["vault-agent-injector"], "bound_service_account_namespaces": ["kube-system"], "token_policies": ["test"]}`,
			"role2": `{"bound_service_account_names": ["default"], "bound_service_account_namespaces": ["default"], "token_policies": ["test"]}`,
		}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return(nil, nil)
		vaultClient.On("CreateRole", "role1", mock.Anything).Return(nil)
		vaultClient.On("CreateRole", "role2", mock.Anything).Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{"kube-system", "default"}, nil)
		k8sClient.On("GetServiceAccounts", "kube-system", serviceAccountAnnotations).Return([]string{}, nil)
		k8sClient.On("GetServiceAccounts", "default", serviceAccountAnnotations).Return([]string{}, nil)
		k8sClient.On("CreateServiceAccount", "kube-system", "vault-agent-injector", serviceAccountAnnotations).Return(errors.New("test failure"))
		k8sClient.On("CreateServiceAccount", "default", "default", serviceAccountAnnotations).Return(nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when list roles request fails then no roles are deleted", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return(nil, errors.New("failed to list roles"))
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return(nil, nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when one vault role deletion fails then flow does not stop and other vault roles are deleted", func(t *testing.T) {

		configMapData := map[string]string{}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{"role1", "role2", "role3"}, nil)
		vaultClient.On("DeleteRole", "role1").Return(errors.New("failed to delete role")).Once()
		vaultClient.On("DeleteRole", "role2", mock.Anything).Return(nil).Once()
		vaultClient.On("DeleteRole", "role3", mock.Anything).Return(nil).Once()
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{}, nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})

	t.Run("when one vault role creation fails then flow does not stop and other vault roles are created", func(t *testing.T) {

		configMapData := map[string]string{
			"role1": `{"bound_service_account_names": ["vault-agent-injector"], "bound_service_account_namespaces": ["kube-system"], "token_policies": ["test"]}`,
			"role2": `{"bound_service_account_names": ["default"], "bound_service_account_namespaces": ["default"], "token_policies": ["test"]}`,
		}
		vaultClient := new(VaultClientMock)
		vaultClient.On("ListRoles").Return([]string{}, nil)
		vaultClient.On("CreateRole", "role1", mock.Anything).Return(errors.New("test failure"))
		vaultClient.On("CreateRole", "role2", mock.Anything).Return(nil)
		k8sClient := new(K8sClientMock)
		k8sClient.On("GetConfigMapData", vaultAuthConfigNamespace, vaultAuthConfigMap).Return(configMapData, nil)
		k8sClient.On("GetNamespaces").Return([]string{}, nil)

		a := NewAuth(testConfig, vaultClient, k8sClient)
		a.initServiceAccounts()
		k8sClient.AssertExpectations(t)
	})
}

// --- mocks ---

type VaultClientMock struct {
	mock.Mock
}

func (m *VaultClientMock) InitAuthKubernetes(k8sHost string, k8sCA []byte, tokenReviewerJWT []byte) error {
	return m.Called(k8sHost, k8sCA, tokenReviewerJWT).Error(0)
}

func (m *VaultClientMock) ListRoles() ([]string, error) {

	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *VaultClientMock) DeleteRole(role string) error {
	return m.Called(role).Error(0)
}

func (m *VaultClientMock) CreateRole(namespace string, role vault.Role) error {
	return m.Called(namespace, role).Error(0)
}

// --- ---

type K8sClientMock struct {
	mock.Mock
}

func (m *K8sClientMock) GetNamespaces() ([]string, error) {

	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *K8sClientMock) GetConfigMapData(namespace, name string) (map[string]string, error) {

	args := m.Called(namespace, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *K8sClientMock) GetServiceAccounts(namespace string, annotations map[string]string) ([]string, error) {

	args := m.Called(namespace, annotations)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *K8sClientMock) CreateServiceAccount(namespace, serviceAccount string, annotations map[string]string) error {
	return m.Called(namespace, serviceAccount, annotations).Error(0)
}

func (m *K8sClientMock) DeleteServiceAccount(namespace, serviceAccount string) error {
	return m.Called(namespace, serviceAccount).Error(0)
}

func (m *K8sClientMock) GetServiceAccountToken(namespace, serviceAccount string) ([]byte, error) {

	args := m.Called(namespace, serviceAccount)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *K8sClientMock) CreateAuthDelegatorClusterRoleBinding(bindingName, namespace, serviceAccount string) error {
	return m.Called(bindingName, namespace, serviceAccount).Error(0)
}
