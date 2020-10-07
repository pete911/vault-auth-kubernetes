package k8s

import (
	v1 "k8s.io/api/core/v1"
	rbacV1 "k8s.io/api/rbac/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newAuthDelegatorClusterRoleBinding(bindingName, serviceAccountNamespace, serviceAccountName string) *rbacV1.ClusterRoleBinding {

	return &rbacV1.ClusterRoleBinding{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name: bindingName,
		},
		RoleRef: rbacV1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
		},
		Subjects: []rbacV1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: serviceAccountNamespace,
			},
		},
	}
}

func newServiceAccount(namespace, name string, annotations map[string]string) *v1.ServiceAccount {

	return &v1.ServiceAccount{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
	}
}
