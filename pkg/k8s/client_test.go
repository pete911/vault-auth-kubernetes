package k8s

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	apiRBAC "k8s.io/api/rbac/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

var serviceAccountAnnotations = map[string]string{"vak-managed": "true"}

func TestClient_GetNamespaces(t *testing.T) {

	t.Run("when get namespaces request is successful then namespaces names and no error are returned", func(t *testing.T) {

		namespaceMock := new(NamespaceMock)
		namespaceMock.On("List", context.Background(), mock.Anything, mock.Anything).Return(&v1.NamespaceList{Items: []v1.Namespace{
			{ObjectMeta: meta.ObjectMeta{Name: "default"}},
			{ObjectMeta: meta.ObjectMeta{Name: "kube-system"}},
		}}, nil)
		c := Client{namespace: namespaceMock}

		namespaces, err := c.GetNamespaces()
		require.NoError(t, err)

		assert.Equal(t, []string{"default", "kube-system"}, namespaces)
	})

	t.Run("when get namespaces request fails then error is returned", func(t *testing.T) {

		namespaceMock := new(NamespaceMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `internal server error`, Reason: "InternalServerError", Code: 500}}
		namespaceMock.On("List", context.Background(), mock.Anything, mock.Anything).Return(nil, returnErr)
		c := Client{namespace: namespaceMock}

		_, err := c.GetNamespaces()
		require.Error(t, err)
	})
}

func TestClient_GetConfigMap(t *testing.T) {

	t.Run("when returned config map is nil then no error is returned", func(t *testing.T) {

		configMapMock := new(ConfigMapsMock)
		configMapMock.On("Get", context.Background(), "vault-auth-roles", meta.GetOptions{}).Return(nil, nil)
		c := Client{configMapsGetter: &ConfigMapsGetterMock{getter: configMapMock}}

		cm, err := c.GetConfigMapData("kube-system", "vault-auth-roles")
		require.NoError(t, err)
		assert.Nil(t, cm)
	})

	t.Run("when get config map fails then error is returned", func(t *testing.T) {

		configMapMock := new(ConfigMapsMock)
		configMapMock.On("Get", context.Background(), "vault-auth-roles", meta.GetOptions{}).Return(nil, errors.New("test failuer"))
		c := Client{configMapsGetter: &ConfigMapsGetterMock{getter: configMapMock}}

		_, err := c.GetConfigMapData("kube-system", "vault-auth-roles")
		require.Error(t, err)
	})

	t.Run("when get config map is successful then no error is returned", func(t *testing.T) {

		expectedConfigMap := &v1.ConfigMap{
			Data: map[string]string{
				"test-role": `{"bound_service_account_names": ["default"], "bound_service_account_namespaces": ["*"], "token_policies": ["test"]}`,
			},
		}
		configMapMock := new(ConfigMapsMock)
		configMapMock.On("Get", context.Background(), "vault-auth-roles", meta.GetOptions{}).Return(expectedConfigMap, nil)
		c := Client{configMapsGetter: &ConfigMapsGetterMock{getter: configMapMock}}

		actualConfigMapData, err := c.GetConfigMapData("kube-system", "vault-auth-roles")
		require.NoError(t, err)
		assert.Equal(t, expectedConfigMap.Data, actualConfigMapData)
	})
}

func TestClient_GetServiceAccounts(t *testing.T) {

	t.Run("when get service accounts is requested with annotations then only service accounts with these annotations are returned", func(t *testing.T) {

		annotations := map[string]string{"vak-managed": "true"}
		serviceAccounts := &v1.ServiceAccountList{Items: []v1.ServiceAccount{
			{ObjectMeta: meta.ObjectMeta{Name: "default", Annotations: nil}},
			{ObjectMeta: meta.ObjectMeta{Name: "vault", Annotations: annotations}},
		}}
		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("List", context.Background(), meta.ListOptions{}).Return(serviceAccounts, nil)
		c := Client{serviceAccountsGetter: &ServiceAccountsGetterMock{getter: serviceAccountMock}}

		annotatedServiceAccounts, err := c.GetServiceAccounts("default", annotations)
		require.NoError(t, err)
		require.Equal(t, 1, len(annotatedServiceAccounts))
		assert.Equal(t, "vault", annotatedServiceAccounts[0])
	})

	t.Run("when get service accounts is requested with nil annotations then all service accounts are returned", func(t *testing.T) {

		annotations := map[string]string{"vak-managed": "true"}
		serviceAccounts := &v1.ServiceAccountList{Items: []v1.ServiceAccount{
			{ObjectMeta: meta.ObjectMeta{Name: "default", Annotations: nil}},
			{ObjectMeta: meta.ObjectMeta{Name: "vault", Annotations: annotations}},
		}}
		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("List", context.Background(), meta.ListOptions{}).Return(serviceAccounts, nil)
		c := Client{serviceAccountsGetter: &ServiceAccountsGetterMock{getter: serviceAccountMock}}

		annotatedServiceAccounts, err := c.GetServiceAccounts("default", nil)
		require.NoError(t, err)
		require.Equal(t, 2, len(annotatedServiceAccounts))
		assert.Equal(t, "default", annotatedServiceAccounts[0])
		assert.Equal(t, "vault", annotatedServiceAccounts[1])
	})

	t.Run("when get service accounts fails then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("List", context.Background(), meta.ListOptions{}).Return(nil, errors.New("test failure"))
		c := Client{serviceAccountsGetter: &ServiceAccountsGetterMock{getter: serviceAccountMock}}

		_, err := c.GetServiceAccounts("default", nil)
		require.Error(t, err)
	})
}

func TestClient_CreateServiceAccount(t *testing.T) {

	t.Run("when service account is created in non existing namespace then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `namespace "pete-test" not found`, Reason: "NotFound", Code: 404}}
		serviceAccountMock.On("Create", context.Background(), mock.Anything, mock.Anything).Return(nil, returnErr)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.CreateServiceAccount("pete-test", "pete-test", serviceAccountAnnotations)
		require.Error(t, err)
		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when creating already existing service account then no error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `serviceaccounts "default" already exists`, Reason: "AlreadyExists", Code: 409}}
		serviceAccountMock.On("Create", context.Background(), mock.Anything, mock.Anything).Return(nil, returnErr)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.CreateServiceAccount("default", "default", serviceAccountAnnotations)
		require.NoError(t, err)

		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when new service account is created then no error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Create", context.Background(), mock.Anything, mock.Anything).Return(nil, nil)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.CreateServiceAccount("default", "default", serviceAccountAnnotations)
		require.NoError(t, err)

		serviceAccountMock.AssertExpectations(t)
	})
}

func TestClient_DeleteServiceAccount(t *testing.T) {

	t.Run("when non existing service account is deleted then no error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `serviceaccounts "token-reviewer" not found`, Reason: "NotFound", Code: 404}}
		serviceAccountMock.On("Delete", context.Background(), "token-reviewer", mock.Anything).Return(returnErr)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.DeleteServiceAccount("default", "token-reviewer")
		require.NoError(t, err)

		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when existing service account is deleted then no error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Delete", context.Background(), "token-reviewer", mock.Anything).Return(nil)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.DeleteServiceAccount("default", "token-reviewer")
		require.NoError(t, err)

		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when service account delete fails then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `internal server error`, Reason: "InternalServerError", Code: 500}}
		serviceAccountMock.On("Delete", context.Background(), "token-reviewer", mock.Anything).Return(returnErr)
		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		err := c.DeleteServiceAccount("default", "token-reviewer")
		require.Error(t, err)

		serviceAccountMock.AssertExpectations(t)
	})
}

func TestClient_GetServiceAccountToken(t *testing.T) {

	t.Run("when service account has references to existing token then token and no error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{Secrets: []v1.ObjectReference{{Name: "default-token-abc"}}}, nil)

		secretsMock := new(SecretsMock)
		secretsMock.On("Get", context.Background(), "default-token-abc", mock.Anything).Return(&v1.Secret{Data: map[string][]byte{"token": []byte("base64 token")}}, nil)
		c := Client{
			serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock},
			secretsGetter:         SecretsGetterMock{getter: secretsMock},
		}

		token, err := c.GetServiceAccountToken("default", "default")
		require.NoError(t, err)

		assert.Equal(t, []byte("base64 token"), token)
		serviceAccountMock.AssertExpectations(t)
		secretsMock.AssertExpectations(t)
	})

	t.Run("when service account cannot be retrieved then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `serviceaccount "default" not found`, Reason: "NotFound", Code: 404}}
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(nil, returnErr)

		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		_, err := c.GetServiceAccountToken("default", "default")
		require.Error(t, err)
		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when service account does not have any secrets then retrieval is re-tried", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{}, nil).Once()
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{}, nil).Once()
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{Secrets: []v1.ObjectReference{{Name: "default-token-abc"}}}, nil).Once()

		secretsMock := new(SecretsMock)
		secretsMock.On("Get", context.Background(), "default-token-abc", mock.Anything).Return(&v1.Secret{Data: map[string][]byte{"token": []byte("base64 token")}}, nil)
		c := Client{
			serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock},
			secretsGetter:         SecretsGetterMock{getter: secretsMock},
		}

		token, err := c.GetServiceAccountToken("default", "default")
		require.NoError(t, err)

		assert.Equal(t, []byte("base64 token"), token)
		serviceAccountMock.AssertExpectations(t)
		secretsMock.AssertExpectations(t)
	})

	t.Run("when service account does not have any secrets even on multiple retries then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{}, nil)

		c := Client{serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock}}

		_, err := c.GetServiceAccountToken("default", "default")
		require.Error(t, err)
		serviceAccountMock.AssertExpectations(t)
	})

	t.Run("when service account's secret does not have token data field then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{Secrets: []v1.ObjectReference{{Name: "default-token-abc"}}}, nil)

		secretsMock := new(SecretsMock)
		// data contains namespace, but no token field
		secretsMock.On("Get", context.Background(), "default-token-abc", mock.Anything).Return(&v1.Secret{Data: map[string][]byte{"namespace": []byte("default")}}, nil)
		c := Client{
			serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock},
			secretsGetter:         SecretsGetterMock{getter: secretsMock},
		}

		_, err := c.GetServiceAccountToken("default", "default")
		require.Error(t, err)
		serviceAccountMock.AssertExpectations(t)
		secretsMock.AssertExpectations(t)
	})

	t.Run("when service account's secret retrieval fails then error is returned", func(t *testing.T) {

		serviceAccountMock := new(ServiceAccountMock)
		serviceAccountMock.On("Get", context.Background(), "default", mock.Anything).Return(&v1.ServiceAccount{Secrets: []v1.ObjectReference{{Name: "default-token-abc"}}}, nil)

		secretsMock := new(SecretsMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `secret "default-token-abc" not found`, Reason: "NotFound", Code: 404}}
		secretsMock.On("Get", context.Background(), "default-token-abc", mock.Anything).Return(nil, returnErr)
		c := Client{
			serviceAccountsGetter: ServiceAccountsGetterMock{getter: serviceAccountMock},
			secretsGetter:         SecretsGetterMock{getter: secretsMock},
		}

		_, err := c.GetServiceAccountToken("default", "default")
		require.Error(t, err)
		serviceAccountMock.AssertExpectations(t)
		secretsMock.AssertExpectations(t)
	})
}

func TestClient_CreateAuthDelegatorClusterRoleBinding(t *testing.T) {

	t.Run("when cluster role binding does not exist then new role binding is created and no error returned", func(t *testing.T) {

		clusterRoleBindingMock := new(ClusterRoleBindingMock)
		expectedRoleBinding := newAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `clusterrolebinding "vault-auth-token-reviewer" not found`, Reason: "NotFound", Code: 404}}
		clusterRoleBindingMock.On("Get", context.Background(), "vault-auth-token-reviewer", mock.Anything).Return(nil, returnErr)
		clusterRoleBindingMock.On("Create", context.Background(), expectedRoleBinding, mock.Anything).Return(nil, nil)
		c := Client{clusterRoleBinding: clusterRoleBindingMock}

		err := c.CreateAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		require.NoError(t, err)
		clusterRoleBindingMock.AssertExpectations(t)
	})

	t.Run("when get cluster role binding call fails then error is returned", func(t *testing.T) {

		clusterRoleBindingMock := new(ClusterRoleBindingMock)
		returnErr := &apiErrors.StatusError{ErrStatus: meta.Status{Status: "Failure", Message: `internal server error`, Reason: "InternalServerError", Code: 500}}
		clusterRoleBindingMock.On("Get", context.Background(), "vault-auth-token-reviewer", mock.Anything).Return(nil, returnErr)
		c := Client{clusterRoleBinding: clusterRoleBindingMock}

		err := c.CreateAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		require.Error(t, err)
		clusterRoleBindingMock.AssertExpectations(t)
	})

	t.Run("when cluster role binding already exists and is the same then nothing is created and no error returned", func(t *testing.T) {

		clusterRoleBindingMock := new(ClusterRoleBindingMock)
		expectedRoleBinding := newAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		clusterRoleBindingMock.On("Get", context.Background(), "vault-auth-token-reviewer", mock.Anything).Return(expectedRoleBinding, nil)
		c := Client{clusterRoleBinding: clusterRoleBindingMock}

		err := c.CreateAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		require.NoError(t, err)
		clusterRoleBindingMock.AssertExpectations(t)
	})

	t.Run("when cluster role binding already exists and is not the same then it is updated and no error returned", func(t *testing.T) {

		clusterRoleBindingMock := new(ClusterRoleBindingMock)
		expectedExistingRoleBinding := newAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "default", "default")
		expectedNewRoleBinding := newAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		clusterRoleBindingMock.On("Get", context.Background(), "vault-auth-token-reviewer", mock.Anything).Return(expectedExistingRoleBinding, nil)
		clusterRoleBindingMock.On("Update", context.Background(), expectedNewRoleBinding, mock.Anything).Return(nil, nil)
		c := Client{clusterRoleBinding: clusterRoleBindingMock}

		err := c.CreateAuthDelegatorClusterRoleBinding("vault-auth-token-reviewer", "vault-auth", "token-reviewer")
		require.NoError(t, err)
		clusterRoleBindingMock.AssertExpectations(t)
	})
}

// --- mocks ---

type ClusterRoleBindingMock struct {
	mock.Mock
}

func (m *ClusterRoleBindingMock) Create(ctx context.Context, rb *apiRBAC.ClusterRoleBinding, options meta.CreateOptions) (*apiRBAC.ClusterRoleBinding, error) {

	args := m.Called(ctx, rb, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*apiRBAC.ClusterRoleBinding), args.Error(1)
}

func (m *ClusterRoleBindingMock) Update(ctx context.Context, rb *apiRBAC.ClusterRoleBinding, options meta.UpdateOptions) (*apiRBAC.ClusterRoleBinding, error) {

	args := m.Called(ctx, rb, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*apiRBAC.ClusterRoleBinding), args.Error(1)
}

func (m *ClusterRoleBindingMock) Get(ctx context.Context, name string, options meta.GetOptions) (*apiRBAC.ClusterRoleBinding, error) {

	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*apiRBAC.ClusterRoleBinding), args.Error(1)
}

// --- ---

type ServiceAccountMock struct {
	mock.Mock
}

func (m *ServiceAccountMock) Create(ctx context.Context, sa *v1.ServiceAccount, opts meta.CreateOptions) (*v1.ServiceAccount, error) {

	args := m.Called(ctx, sa, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.ServiceAccount), args.Error(1)
}

func (m *ServiceAccountMock) Delete(ctx context.Context, name string, options meta.DeleteOptions) error {

	args := m.Called(ctx, name, options)
	return args.Error(0)
}

func (m *ServiceAccountMock) Get(ctx context.Context, name string, options meta.GetOptions) (*v1.ServiceAccount, error) {

	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.ServiceAccount), args.Error(1)
}

func (m *ServiceAccountMock) List(ctx context.Context, options meta.ListOptions) (*v1.ServiceAccountList, error) {

	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.ServiceAccountList), args.Error(1)
}

// --- ---

type SecretsMock struct {
	mock.Mock
}

func (m SecretsMock) Get(ctx context.Context, name string, options meta.GetOptions) (*v1.Secret, error) {

	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.Secret), args.Error(1)
}

// --- ---

type ConfigMapsMock struct {
	mock.Mock
}

func (m ConfigMapsMock) Get(ctx context.Context, name string, options meta.GetOptions) (*v1.ConfigMap, error) {

	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.ConfigMap), args.Error(1)
}

// --- ---

type ServiceAccountsGetterMock struct {
	getter *ServiceAccountMock
}

func (s ServiceAccountsGetterMock) ServiceAccounts(namespace string) serviceAccountInterface {
	return s.getter
}

// --- ---

type SecretsGetterMock struct {
	getter *SecretsMock
}

func (s SecretsGetterMock) Secrets(namespace string) secretsInterface {
	return s.getter
}

// --- ---

type ConfigMapsGetterMock struct {
	getter *ConfigMapsMock
}

func (c ConfigMapsGetterMock) ConfigMaps(namespace string) configMapsInterface {
	return c.getter
}

// --- ---

type NamespaceMock struct {
	mock.Mock
}

func (m NamespaceMock) List(ctx context.Context, opts meta.ListOptions) (*v1.NamespaceList, error) {

	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*v1.NamespaceList), args.Error(1)
}
