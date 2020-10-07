package main

import (
	"crypto/tls"
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/logger"
	"github.com/pete911/vault-auth-kubernetes/pkg/auth"
	"github.com/pete911/vault-auth-kubernetes/pkg/k8s"
	"github.com/pete911/vault-auth-kubernetes/pkg/vault"
	"net/http"
	"os"
	"time"
)

const httpClientTimeoutSeconds = 10

func main() {

	flags, err := ParseFlags()
	if err != nil {
		logger.Errorf("parse flags: %v", err)
		os.Exit(1)
	}

	logger.Logf("starting vault-auth-kubernetes with flags: %s", flags)
	httpClient := newHttpClient(true)

	vaultClient := newVaultClient(flags, httpClient)

	kubeconfig, err := k8s.LoadKubeconfig(flags.Kubeconfig)
	if err != nil {
		logger.Errorf("get kubeconfig: %v", err)
		os.Exit(1)
	}
	k8sClient := k8s.NewClient(kubeconfig.Clientset)
	if flags.VaultKubeHost == "" {
		flags.VaultKubeHost = kubeconfig.Host
		logger.Logf("vault-kube-host not set, setting host to %s (from kubeconfig)", flags.VaultKubeHost)
	}

	authConfig := auth.Config{
		VaultMount: flags.VaultMount,
		K8sHost:    flags.VaultKubeHost,
		K8sCA:      kubeconfig.CA,
	}

	if err := auth.NewAuth(authConfig, vaultClient, k8sClient).Run(); err != nil {
		logger.Errorf("auth run: %v", err)
		os.Exit(1)
	}
}

func newVaultClient(flags Flags, httpClient *http.Client) *vault.Client {

	vaultConfig := vault.Config{
		HttpClient: httpClient,
		Host:       flags.VaultHost,
		RoleId:     flags.VaultRoleId,
		SecretId:   flags.VaultSecretId,
	}
	vaultClient, err := vault.NewClient(vaultConfig, fmt.Sprintf("kubernetes/%s", flags.VaultMount))
	if err != nil {
		logger.Errorf("new vault client: %v", err)
		os.Exit(1)
	}
	return vaultClient
}

func newHttpClient(insecure bool) *http.Client {

	var transport *http.Transport
	if insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return &http.Client{Transport: transport, Timeout: httpClientTimeoutSeconds * time.Second}
}
