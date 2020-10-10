[![Build Status](https://travis-ci.com/pete911/vault-auth-kubernetes.svg?branch=master)](https://travis-ci.com/pete911/vault-auth-kubernetes)

# vault-auth-kubernetes

Project enables [vault kubernetes auth method](https://www.vaultproject.io/api/auth/kubernetes) at
`auth/kubernetes/<account>/<cluster>` location in vault and creates
[vault roles](https://www.vaultproject.io/api/auth/kubernetes#create-role) per namespace, with policies configured in
configmap `vault-auth-roles` in `vault-auth` namespace:
```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-auth-roles
  namespace: vault-auth
  labels:
    app: vault-auth-kubernetes
data:
  default: |-
    {
      "bound_service_account_names": ["vault-agent-injector", "default"],
      "bound_service_account_namespaces": ["kube-system", "default"],
      "token_policies": ["test"]
    }
  test: |-
    {
      "bound_service_account_names": ["vault-agent-injector"],
      "bound_service_account_namespaces": ["kube-system"],
      "token_policies": ["test", "default"]
    }
```
Where data key is the name of the vault role to be created and value us json representation of
[vault role](https://www.vaultproject.io/api-docs/auth/kubernetes#create-role)

Service account `token-reviewer` to review tokens (authenticate) is created in `vault-auth` namespace with
`vault-auth-token-reviewer` cluster role binding (bound to `system:auth-delegator` role). Service account
`vault-agent-injector` is then created for every namespace defined in the configmap.

`vault-agent-injector` service account maps to vault role and enables
[kube auth login](https://www.vaultproject.io/api/auth/kubernetes#login).

## requirements

[Vault](https://www.vaultproject.io/) needs to be already configured with
[policy](https://learn.hashicorp.com/vault/identity-access-management/iam-policies#prerequisites) that allows
`vault-auth-kubernetes` to create/update/delete auth mount and roles. This is an example of the policy if your mount
path contains 2 parts (e.g. `environment/cluster-name`), otherwise replace `/+/+` with number of parts in your mount:

```
path "sys/auth" {
  capabilities = ["list", "read"]
}
path "sys/auth/kubernetes/+/+" {
  capabilities = ["list", "read", "create", "update", "delete", "sudo"]
}
path "auth/kubernetes/+/+/config" {
  capabilities = ["list", "read", "create", "update", "sudo"]
}
path "auth/kubernetes/+/+/role/+" {
  capabilities = ["list", "read", "create", "update", "delete"]
}
```

It is also expected to have [vault approle](https://www.vaultproject.io/api-docs/auth/approle) auth method enabled and
approle created with the above policy, so we can get
[role-id](https://www.vaultproject.io/api-docs/auth/approle#read-approle-role-id) and generate
[role-secret-id](https://www.vaultproject.io/api-docs/auth/approle#generate-new-secret-id). It is expected to have
secret with the role id and secret id named `vault-auth-kubernetes` in the release namespace:
```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-kubernetes
  namespace: <release-namespace>
data:
  VAK_VAULT_ROLE_ID: <base64-encoded-role-id>
  VAK_VAULT_SECRET_ID: <base64-encoded-secret-id>
```

## design

```
+-------------+             +-------------+             +-------------+
|     VAK     |             |    vault    |             |  kube-api   |
+-------------+             +-------------+             +-------------+
       |                           |                           |
      +-+-----------|create reviewer svc. account|----------->+-+
      | |                          |                          | |
      +-+                          |                          +-+
       |                           |                           |
      +-+--------|get reviewer svc. account jwt token|------->+-+
      | |                          |                          | |
      +-+                          |                          +-+
       |                           |                           |
      +-+---|mount kube auth|---->+-+                          |
      | |                         | |                          |
      +-+                         +-+                          |
       |                           |                           |
      +-+---|setup kube auth|---->+-+                          |
      | |                         | |                          |
      +-+                         +-+                          |
       |                           |                           |
      +-+----|get config map (vault auth kubernetes role)|--->+-+
      | |                          |                          | |
      +-+                          |                          +-+
       |                           |                           |
      +-+------------|create/delete svc. accounts|----------->+-+
      | |                          |                          | |
      +-+                          |                          +-+
       |                           |                           |
      +-+-|create/delete roles|-->+-+                          |
      | |                         | |                          |
      +-+                         +-+                          |
```

## build and run

It is recommended to use [helm chart](charts/vault-auth-kubernetes), that uses released image from
[dockerhub](https://hub.docker.com/repository/docker/pete911/vault-auth-kubernetes), but for testing purposes, project
can be run locally - `make build` and:
```shell script
./vault-auth-kubernetes \
--vault-host <host> \
--vault-mount <vault-mount>\
--vault-role-id <role-id> \
--vault-secret-id <secret-id>
```

If `kubeconfig` flag is not supplied, it is assumed application runs from within the cluster and service account token
and ca files are used from `/var/run/secrets/kubernetes.io/serviceaccount/token` and
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` files.

Environment variables can be used instead of flags as well:

```
flag                    env. var.           description
-kubeconfig             KUBECONFIG          path to kubeconfig file, or empty for in-cluster kubeconfig
-vault-host             VAK_VAULT_HOST      vault host
-vault-kube-host        VAK_VAULT_KUBE_HOST kubernetes API that can be reached from vault, defaults to host from kubeconfig
-vault-mount            VAK_VAULT_MOUNT     vault kubernetes mount e.g cluster-name, or environment/cluster-name
-vault-role-id          VAK_VAULT_ROLE_ID   vault role id
-vault-secret-id        VAK_VAULT_SECRET_ID vault secret id
```

## test

 - `make test` - requires go and helm installed
 - `make integration-test` - requires minikube
 - `make e2e-test` - end to end test, requires minikube
