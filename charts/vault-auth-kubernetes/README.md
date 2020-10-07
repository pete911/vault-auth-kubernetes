# Vault auth kubernetes chart

Helm chart for `vault-auth-kubernetes`.

## Values

| Parameter     | Description                       | Default   |
| ------------- | --------------------------------- | --------- |
| image         | vault auth kubernetes image       |   -       |
| vaultHost     | vault host with scheme and port   |   -       |
| vaultMount    | [vault kubernetes mount path](https://www.vaultproject.io/api-docs/auth/kubernetes#configure-method) |   -       |

User needs to make sure secret with `VAK_VAULT_ROLE_ID` and `VAK_VAULT_SECRET_ID` data is present in the cluster, e.g:
```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-kubernetes
  namespace: kube-system
data:
  VAK_VAULT_ROLE_ID: YWRtaW4=
  VAK_VAULT_SECRET_ID: MWYyZDFlMmU2N2Rm
```
Metadata name has to match `{{ .Release.Name }}` and namespace `{{ .Release.Namesapce }}`.
