package auth

import (
	"github.com/pete911/vault-auth-kubernetes/logger"
	"github.com/pete911/vault-auth-kubernetes/pkg/vault"
)

type vaultRoles map[string]vault.Role

func newVaultRoles(configMapData map[string]string) vaultRoles {

	roles := make(vaultRoles)
	for roleName, rawRole := range configMapData {
		role, err := vault.NewRole([]byte(rawRole))
		if err != nil {
			logger.Errorf("new vault role %s from config map %s in %s namespace: %v",
				roleName, vaultAuthConfigMap, vaultAuthConfigNamespace, err)
			continue
		}
		roles[roleName] = role
	}
	return roles
}

func (v vaultRoles) getServiceAccountsSetByNamespace() map[string]map[string]struct{} {

	serviceAccountsByNamespace := make(map[string]map[string]struct{})
	for _, vaultRole := range v {
		for _, namespace := range vaultRole.BoundServiceAccountNamespaces {
			if _, ok := serviceAccountsByNamespace[namespace]; !ok {
				serviceAccountsByNamespace[namespace] = make(map[string]struct{})
			}
			for _, serviceAccount := range vaultRole.BoundServiceAccountNames {
				serviceAccountsByNamespace[namespace][serviceAccount] = struct{}{}
			}
		}
	}
	return serviceAccountsByNamespace
}
