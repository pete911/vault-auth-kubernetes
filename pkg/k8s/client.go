package k8s

import (
	"context"
	"errors"
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/logger"
	v1 "k8s.io/api/core/v1"
	apiRBAC "k8s.io/api/rbac/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/client-go/kubernetes/typed/core/v1"
	"reflect"
	"time"
)

// --- stripped down kubernetes interfaces to simplify testing ---

type namespaceInterface interface {
	List(ctx context.Context, opts meta.ListOptions) (*v1.NamespaceList, error)
}

type clusterRoleBindingInterface interface {
	Create(ctx context.Context, clusterRoleBinding *apiRBAC.ClusterRoleBinding, opts meta.CreateOptions) (*apiRBAC.ClusterRoleBinding, error)
	Update(ctx context.Context, clusterRoleBinding *apiRBAC.ClusterRoleBinding, opts meta.UpdateOptions) (*apiRBAC.ClusterRoleBinding, error)
	Get(ctx context.Context, name string, opts meta.GetOptions) (*apiRBAC.ClusterRoleBinding, error)
}

type serviceAccountInterface interface {
	Create(ctx context.Context, serviceAccount *v1.ServiceAccount, opts meta.CreateOptions) (*v1.ServiceAccount, error)
	Delete(ctx context.Context, name string, opts meta.DeleteOptions) error
	Get(ctx context.Context, name string, opts meta.GetOptions) (*v1.ServiceAccount, error)
	List(ctx context.Context, opts meta.ListOptions) (*v1.ServiceAccountList, error)
}

type serviceAccountsGetter interface {
	ServiceAccounts(namespace string) serviceAccountInterface
}

type secretsInterface interface {
	Get(ctx context.Context, name string, opts meta.GetOptions) (*v1.Secret, error)
}

type secretsGetter interface {
	Secrets(namespace string) secretsInterface
}

type configMapsInterface interface {
	Get(ctx context.Context, name string, opts meta.GetOptions) (*v1.ConfigMap, error)
}

type configMapsGetter interface {
	ConfigMaps(namespace string) configMapsInterface
}

// --- ------------------------------------------------------- ---

type serviceAccounts struct {
	getter core.ServiceAccountsGetter
}

func (s serviceAccounts) ServiceAccounts(namespace string) serviceAccountInterface {
	return s.getter.ServiceAccounts(namespace)
}

type secrets struct {
	getter core.SecretsGetter
}

func (s secrets) Secrets(namespace string) secretsInterface {
	return s.getter.Secrets(namespace)
}

type configMaps struct {
	getter core.ConfigMapsGetter
}

func (c configMaps) ConfigMaps(namespace string) configMapsInterface {
	return c.getter.ConfigMaps(namespace)
}

// --- ------------------------------------------------------- ---

type Client struct {
	namespace             namespaceInterface
	serviceAccountsGetter serviceAccountsGetter
	secretsGetter         secretsGetter
	configMapsGetter      configMapsGetter
	clusterRoleBinding    clusterRoleBindingInterface
}

func NewClient(clientSet *kubernetes.Clientset) Client {

	return Client{
		namespace:             clientSet.CoreV1().Namespaces(),
		serviceAccountsGetter: serviceAccounts{getter: clientSet.CoreV1()},
		secretsGetter:         secrets{getter: clientSet.CoreV1()},
		configMapsGetter:      configMaps{getter: clientSet.CoreV1()},
		clusterRoleBinding:    clientSet.RbacV1().ClusterRoleBindings(),
	}
}

func (c Client) GetNamespaces() ([]string, error) {

	namespaceList, err := c.namespace.List(context.Background(), meta.ListOptions{})
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, namespace := range namespaceList.Items {
		namespaces = append(namespaces, namespace.Name)
	}
	return namespaces, nil
}

func (c Client) GetConfigMapData(namespace, name string) (map[string]string, error) {

	cm, err := c.configMapsGetter.ConfigMaps(namespace).Get(context.Background(), name, meta.GetOptions{})
	if err != nil || cm == nil {
		return nil, err
	}
	return cm.Data, nil
}

func (c Client) GetServiceAccounts(namespace string, annotations map[string]string) ([]string, error) {

	serviceAccountsList, err := c.serviceAccountsGetter.ServiceAccounts(namespace).List(context.Background(), meta.ListOptions{})
	if err != nil {
		return nil, err
	}

	var serviceAccountNames []string
	for _, serviceAccount := range serviceAccountsList.Items {
		if len(annotations) == 0 {
			serviceAccountNames = append(serviceAccountNames, serviceAccount.Name)
			continue
		}
		for serviceAccountAnnotationKey, serviceAccountAnnotationValue := range serviceAccount.Annotations {
			if annotations[serviceAccountAnnotationKey] != serviceAccountAnnotationValue {
				continue
			}
			serviceAccountNames = append(serviceAccountNames, serviceAccount.Name)
		}
	}
	return serviceAccountNames, nil
}

func (c Client) CreateServiceAccount(namespace, name string, annotations map[string]string) error {

	serviceAccount := newServiceAccount(namespace, name, annotations)
	if _, err := c.serviceAccountsGetter.ServiceAccounts(namespace).Create(context.Background(), serviceAccount, meta.CreateOptions{}); err != nil {
		if apiErrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	logger.Logf("service account %s in %s namespace created", name, namespace)
	return nil
}

func (c Client) DeleteServiceAccount(namespace, name string) error {

	if err := c.serviceAccountsGetter.ServiceAccounts(namespace).Delete(context.Background(), name, meta.DeleteOptions{}); err != nil {
		if apiErrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	logger.Logf("service account %s in %s namespace deleted", name, namespace)
	return nil
}

func (c Client) GetServiceAccountToken(serviceAccountNamespace, serviceAccountName string) ([]byte, error) {

	serviceAccount, err := c.getServiceAccount(serviceAccountNamespace, serviceAccountName, 5)
	if err != nil {
		return nil, err
	}

	secret, err := c.secretsGetter.Secrets(serviceAccountNamespace).Get(context.Background(), serviceAccount.Secrets[0].Name, meta.GetOptions{})
	if err != nil {
		return nil, err
	}

	// data map has 'ca.crt', 'namespace' and 'token' keys
	// ca.crt contains the whole chain, not just 'certificate-authority' that is in kubeconfig
	if token, ok := secret.Data["token"]; ok {
		logger.Logf("token for service account %s in %s namespace retrieved", serviceAccountName, serviceAccountNamespace)
		return token, nil
	}
	return nil, fmt.Errorf("%s secret does not have data.token field", secret.Name)
}

// secret/token is not set initially on new service account, it takes some time for kubernetes to create it
// it is advisable to set retries to 2 or higher to make sure that secrets are populated
func (c Client) getServiceAccount(namespace, name string, retries int) (*v1.ServiceAccount, error) {

	serviceAccount, err := c.serviceAccountsGetter.ServiceAccounts(namespace).Get(context.Background(), name, meta.GetOptions{})
	if err != nil {
		return nil, err
	}
	if len(serviceAccount.Secrets) == 0 {
		if retries < 1 {
			return nil, errors.New("number of retries exceeded")
		}
		logger.Logf("service account %q does not have any secrets, retrying again in 50 milliseconds", name)
		time.Sleep(50 * time.Millisecond)
		return c.getServiceAccount(namespace, name, retries-1)
	}
	return serviceAccount, nil
}

func (c Client) CreateAuthDelegatorClusterRoleBinding(bindingName, serviceAccountNamespace, serviceAccountName string) error {

	clusterRoleBinding := newAuthDelegatorClusterRoleBinding(bindingName, serviceAccountNamespace, serviceAccountName)
	return c.createClusterRoleBinding(clusterRoleBinding)
}

func (c Client) createClusterRoleBinding(clusterRoleBinding *apiRBAC.ClusterRoleBinding) error {

	existingClusterRoleBinding, err := c.clusterRoleBinding.Get(context.Background(), clusterRoleBinding.Name, meta.GetOptions{})
	if err != nil {
		if apiErrors.IsNotFound(err) {
			// new role binding
			logger.Logf("creating new %s cluster role binding", clusterRoleBinding.Name)
			_, err = c.clusterRoleBinding.Create(context.Background(), clusterRoleBinding, meta.CreateOptions{})
			return err
		}
		return err
	}

	if isClusterRoleBindingEqual(clusterRoleBinding, existingClusterRoleBinding) {
		return nil
	}

	logger.Logf("updating role binding %s", existingClusterRoleBinding.Name)
	_, err = c.clusterRoleBinding.Update(context.Background(), clusterRoleBinding, meta.UpdateOptions{})
	return err
}

func isClusterRoleBindingEqual(rb1, rb2 *apiRBAC.ClusterRoleBinding) bool {

	equalMeta := rb1.Name == rb2.Name
	equalRoles := reflect.DeepEqual(rb1.RoleRef, rb2.RoleRef)
	equalSubjects := reflect.DeepEqual(rb1.Subjects, rb2.Subjects)
	return equalMeta && equalRoles && equalSubjects
}
