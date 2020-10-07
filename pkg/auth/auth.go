package auth

import (
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/logger"
	"github.com/pete911/vault-auth-kubernetes/pkg/vault"
	"time"
)

const (
	// token reviewer - https://www.vaultproject.io/docs/auth/kubernetes#configuring-kubernetes
	tokenReviewerServiceAccount     = "token-reviewer"
	tokenReviewerNamespace          = "vault-auth"
	tokenReviewerClusterRoleBinding = "vault-auth-token-reviewer"

	// vault auth kubernetes roles https://www.vaultproject.io/api-docs/auth/kubernetes#create-role
	vaultAuthConfigReloadSeconds = 10
	vaultAuthConfigNamespace     = "vault-auth"
	vaultAuthConfigMap           = "vault-auth-roles"
)

var (
	serviceAccountAnnotations = map[string]string{"vak-managed": "true"}
)

type VaultClient interface {
	InitAuthKubernetes(k8sHost string, k8sCA []byte, tokenReviewerJWT []byte) error
	ListRoles() ([]string, error)
	DeleteRole(role string) error
	CreateRole(namespace string, role vault.Role) error
}

type K8sClient interface {
	GetNamespaces() ([]string, error)
	GetConfigMapData(namespace, name string) (map[string]string, error)
	GetServiceAccounts(namespace string, annotations map[string]string) ([]string, error)
	DeleteServiceAccount(namespace, serviceAccount string) error
	CreateServiceAccount(namespace, serviceAccount string, annotations map[string]string) error
	GetServiceAccountToken(namespace, serviceAccount string) ([]byte, error)
	CreateAuthDelegatorClusterRoleBinding(bindingName, namespace, serviceAccount string) error
}

type Config struct {
	VaultMount string
	K8sHost    string
	K8sCA      []byte
}

type Auth struct {
	config      Config
	vaultClient VaultClient
	k8sClient   K8sClient
}

func NewAuth(config Config, vaultClient VaultClient, k8sClient K8sClient) Auth {

	return Auth{
		config:      config,
		vaultClient: vaultClient,
		k8sClient:   k8sClient,
	}
}

func (a Auth) Run() error {

	if err := a.initTokenReviewer(); err != nil {
		return err
	}

	for {
		a.initServiceAccounts()
		<-time.After(time.Duration(vaultAuthConfigReloadSeconds) * time.Second)
	}
}

func (a Auth) initServiceAccounts() {

	data, err := a.k8sClient.GetConfigMapData(vaultAuthConfigNamespace, vaultAuthConfigMap)
	if err != nil {
		logger.Errorf("get vault auth kubernetes roles from config map %s in %s namespace: %v",
			vaultAuthConfigMap, vaultAuthConfigNamespace, err)
		return
	}

	vaultRoles := newVaultRoles(data)
	serviceAccountsSetByNamespace := vaultRoles.getServiceAccountsSetByNamespace()

	// delete service accounts and roles that are not in vault role config map
	a.deleteServiceAccounts(serviceAccountsSetByNamespace, serviceAccountAnnotations)
	a.deleteVaultRoles(vaultRoles)

	// create service accounts and roles that are in vault role config map
	a.createServiceAccounts(serviceAccountsSetByNamespace)
	a.createVaultRoles(vaultRoles)
}

func (a Auth) deleteServiceAccounts(serviceAccountsSetByNamespace map[string]map[string]struct{}, serviceAccountAnnotations map[string]string) {

	k8sNamespaces, err := a.k8sClient.GetNamespaces()
	if err != nil {
		logger.Errorf("delete service accounts: get namespaces: %v", err)
		return
	}

	for _, k8sNamespace := range k8sNamespaces {
		k8sServiceAccounts, err := a.k8sClient.GetServiceAccounts(k8sNamespace, serviceAccountAnnotations)
		if err != nil {
			logger.Errorf("get service accounts: %v", err)
			continue
		}
		for _, k8sServiceAccount := range k8sServiceAccounts {
			serviceAccountsSet, ok := serviceAccountsSetByNamespace[k8sNamespace]
			// namespace not in vault role, delete all service accounts (annotated with 'vak-managed') under this namespace
			if !ok {
				if err := a.k8sClient.DeleteServiceAccount(k8sNamespace, k8sServiceAccount); err != nil {
					logger.Errorf("service account %s in %s namespace is not in config: delete service account: %v",
						k8sServiceAccount, k8sNamespaces, err)
				}
				continue
			}
			// service account (annotated with 'vak-managed') not in vault role, delete it
			if _, ok := serviceAccountsSet[k8sServiceAccount]; !ok {
				if err := a.k8sClient.DeleteServiceAccount(k8sNamespace, k8sServiceAccount); err != nil {
					logger.Errorf("delete service account: %v", err)
				}
			}
		}
	}
}

func (a Auth) deleteVaultRoles(vaultRolesInConfig vaultRoles) {

	vaultRolesInVault, err := a.vaultClient.ListRoles()
	if err != nil {
		logger.Errorf("delete vault roles: list roles: %v", err)
		return
	}

	for _, vaultRoleInVault := range vaultRolesInVault {
		if _, ok := vaultRolesInConfig[vaultRoleInVault]; !ok {
			if err := a.vaultClient.DeleteRole(vaultRoleInVault); err != nil {
				logger.Errorf("delete vault role: %v", err)
			}
		}
	}
}

func (a Auth) createServiceAccounts(serviceAccountsSetByNamespace map[string]map[string]struct{}) {

	k8sNamespaces, err := a.k8sClient.GetNamespaces()
	if err != nil {
		logger.Errorf("create service accounts: get namespaces: %v", err)
	}

	for _, k8sNamespace := range k8sNamespaces {
		for serviceAccount := range serviceAccountsSetByNamespace[k8sNamespace] {
			if err := a.k8sClient.CreateServiceAccount(k8sNamespace, serviceAccount, serviceAccountAnnotations); err != nil {
				logger.Errorf("create service account: %v", err)
			}
		}
	}
}

func (a Auth) createVaultRoles(vaultRolesInConfig vaultRoles) {

	for roleName, role := range vaultRolesInConfig {
		if err := a.vaultClient.CreateRole(roleName, role); err != nil {
			logger.Errorf("create vault role: %v", err)
		}
	}
}

func (a Auth) initTokenReviewer() error {

	if err := a.k8sClient.CreateServiceAccount(tokenReviewerNamespace, tokenReviewerServiceAccount, nil); err != nil {
		return fmt.Errorf("create service account: %w", err)
	}

	token, err := a.k8sClient.GetServiceAccountToken(tokenReviewerNamespace, tokenReviewerServiceAccount)
	if err != nil {
		return fmt.Errorf("get service account token: %w", err)
	}

	if err := a.k8sClient.CreateAuthDelegatorClusterRoleBinding(tokenReviewerClusterRoleBinding, tokenReviewerNamespace, tokenReviewerServiceAccount); err != nil {
		return fmt.Errorf("create auth delegator cluster role binding: %w", err)
	}
	return a.vaultClient.InitAuthKubernetes(a.config.K8sHost, a.config.K8sCA, token)
}
