package main

import (
	"flag"
	"fmt"
	"gopkg.in/validator.v2"
	"os"
)

type Flags struct {
	Kubeconfig    string
	VaultHost     string `validate:"nonzero"`
	VaultMount    string `validate:"nonzero"`
	VaultKubeHost string
	VaultRoleId   string `validate:"nonzero"`
	VaultSecretId string `validate:"nonzero"`
}

func ParseFlags() (Flags, error) {

	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	kubeconfig := f.String("kubeconfig", getStringEnv("KUBECONFIG", ""), "path to kubeconfig file, or empty for in-cluster kubeconfig")
	vaultHost := f.String("vault-host", getStringEnv("VAK_VAULT_HOST", ""), "vault host")
	vaultMount := f.String("vault-mount", getStringEnv("VAK_VAULT_MOUNT", ""), "vault kubernetes mount e.g cluster-name, or environment/cluster-name")
	vaultKubeHost := f.String("vault-kube-host", getStringEnv("VAK_VAULT_KUBE_HOST", ""), "kubernetes API that can be reached from vault, defaults to host from kubeconfig")
	vaultRoleId := f.String("vault-role-id", getStringEnv("VAK_VAULT_ROLE_ID", ""), "vault role id")
	vaultSecretId := f.String("vault-secret-id", getStringEnv("VAK_VAULT_SECRET_ID", ""), "vault secret id")
	f.Parse(os.Args[1:])

	vakFlags := Flags{
		Kubeconfig:    stringValue(kubeconfig),
		VaultHost:     stringValue(vaultHost),
		VaultMount:    stringValue(vaultMount),
		VaultKubeHost: stringValue(vaultKubeHost),
		VaultRoleId:   stringValue(vaultRoleId),
		VaultSecretId: stringValue(vaultSecretId),
	}

	err := validator.Validate(vakFlags)
	return vakFlags, err
}

func (f Flags) String() string {

	return fmt.Sprintf("kubeconfig: %q vault-host %q vault-mount: %q vault-kube-host: %q vault-role-id ****** vault-secret-id ******",
		f.Kubeconfig, f.VaultHost, f.VaultMount, f.VaultKubeHost)
}

func getStringEnv(envName string, defaultValue string) string {

	env, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}
	return env
}

func stringValue(v *string) string {

	if v == nil {
		return ""
	}
	return *v
}
