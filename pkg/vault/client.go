package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/logger"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	vaultVersion        = "v1"
	kubernetesMountType = "kubernetes"
	httpNumberOfRetries = 3 // it is advisable to set this to 2 or higher, so token can be re-generated if it expires
)

type HttpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Config struct {
	HttpClient HttpClient
	Host       string
	RoleId     string
	SecretId   string
}

type Client struct {
	config Config
	mount  string
	token  string
}

func NewClient(config Config, authK8sMount string) (*Client, error) {

	config.Host = strings.TrimSuffix(config.Host, "/")
	c := &Client{
		mount:  strings.Trim(authK8sMount, "/"),
		config: config,
	}

	if err := c.appRoleLogin(httpNumberOfRetries); err != nil {
		return nil, err
	}
	return c, nil
}

// initialise auth kubernetes, check if there is auth mount 'kubernetes/<account>/<cluster>', if not, mount and tune
// kubeJWT arg is service account JWT used to github the TokenReview API to validate other JWTs during login
func (c *Client) InitAuthKubernetes(kubernetesHost string, kubernetesCACert, tokenReviewerJWT []byte) error {

	logger.Logf("initialising %s kubernetes auth", c.mount)
	mounted, err := c.isAuthKubernetesMounted()
	if err != nil {
		return err
	}
	if mounted {
		logger.Log("kubernetes auth is already mounted")
		return nil
	}

	if err := c.mountAuthKubernetes(); err != nil {
		return err
	}

	if err := c.configureAuthKubernetes(kubernetesHost, kubernetesCACert, tokenReviewerJWT); err != nil {
		return err
	}

	return nil
}

func (c *Client) DeleteAuthKubernetes() error {

	mounted, err := c.isAuthKubernetesMounted()
	if err != nil {
		return err
	}
	if !mounted {
		logger.Log("kubernetes auth is not mounted")
		return nil
	}

	path := fmt.Sprintf("sys/auth/%s", c.mount)
	jsonRequest, err := c.newJsonRequest(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	logger.Logf("deleting auth kubernetes: DELETE %s", path)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler, expectedNotFoundErrorHandler}
	return c.doJsonRequest(jsonRequest, nil, errorHandlers, httpNumberOfRetries)
}

func (c *Client) CreateRole(name string, role Role) error {

	existingRole, err := c.readRole(name)
	if err != nil {
		return err
	}
	if existingRole != nil {
		if role.Equal(*existingRole) {
			return nil
		}
		logger.Logf("role %s has changed", name)
		logger.Logf("old role: %+v", role)
	}

	path := fmt.Sprintf("auth/%s/role/%s", c.mount, name)
	jsonRequest, err := c.newJsonRequest(http.MethodPost, path, role)
	if err != nil {
		return err
	}

	logger.Logf("creating role: POST %s %+v", path, role)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler}
	return c.doJsonRequest(jsonRequest, nil, errorHandlers, httpNumberOfRetries)
}

func (c *Client) DeleteRole(name string) error {

	existingRole, err := c.readRole(name)
	if err != nil || existingRole == nil {
		return err
	}

	path := fmt.Sprintf("auth/%s/role/%s", c.mount, name)
	jsonRequest, err := c.newJsonRequest(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	logger.Logf("deleting role: DELETE %s", path)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler, expectedNotFoundErrorHandler}
	return c.doJsonRequest(jsonRequest, nil, errorHandlers, httpNumberOfRetries)
}

// read role, when 404 is returned from vault, nil role and nil error is returned
func (c *Client) readRole(name string) (*Role, error) {

	path := fmt.Sprintf("auth/%s/role/%s", c.mount, name)
	response := &struct {
		Data *Role `json:"data"`
	}{}

	jsonRequest, err := c.newJsonRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	errorHandlers := []errorHandler{permissionDeniedErrorHandler, expectedNotFoundErrorHandler}
	if err := c.doJsonRequest(jsonRequest, response, errorHandlers, httpNumberOfRetries); err != nil {
		return nil, err
	}
	return response.Data, nil
}

// list roles, when 404 is returned from vault, nil roles and nil error is returned
func (c *Client) ListRoles() ([]string, error) {

	path := fmt.Sprintf("auth/%s/role", c.mount)
	response := struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}{}

	jsonRequest, err := c.newJsonRequest("LIST", path, nil)
	if err != nil {
		return nil, err
	}

	errorHandlers := []errorHandler{permissionDeniedErrorHandler, expectedNotFoundErrorHandler}
	if err := c.doJsonRequest(jsonRequest, &response, errorHandlers, httpNumberOfRetries); err != nil {
		return nil, err
	}
	return response.Data.Keys, nil
}

func (c *Client) mountAuthKubernetes() error {

	path := fmt.Sprintf("sys/auth/%s", c.mount)
	request := struct {
		Type        string            `json:"type"`
		Description string            `json:"description"`
		Config      map[string]string `json:"config,omitempty"`
	}{
		Type:        kubernetesMountType,
		Description: "Kubernetes auth backend for RUN cluster",
		Config:      map[string]string{"max_lease_ttl": "8760h"},
	}

	jsonRequest, err := c.newJsonRequest(http.MethodPost, path, request)
	if err != nil {
		return err
	}

	logger.Logf("mounting auth kubernetes: POST %s", path)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler}
	return c.doJsonRequest(jsonRequest, nil, errorHandlers, httpNumberOfRetries)
}

func (c *Client) configureAuthKubernetes(kubernetesHost string, kubernetesCACert, tokenReviewerJWT []byte) error {

	logger.Logf("kubernetes host: %s", kubernetesHost)
	logger.Logf("kubernetes ca:\n%s", kubernetesCACert)
	path := fmt.Sprintf("auth/%s/config", c.mount)
	request := struct {
		KubernetesHost   string `json:"kubernetes_host"`
		KubernetesCACert string `json:"kubernetes_ca_cert"`
		TokenReviewerJWT string `json:"token_reviewer_jwt"`
	}{
		KubernetesHost:   kubernetesHost,
		KubernetesCACert: string(kubernetesCACert),
		TokenReviewerJWT: string(tokenReviewerJWT),
	}

	jsonRequest, err := c.newJsonRequest(http.MethodPost, path, request)
	if err != nil {
		return err
	}

	logger.Logf("configuring auth kubernetes: POST %s", path)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler}
	return c.doJsonRequest(jsonRequest, nil, errorHandlers, httpNumberOfRetries)
}

func (c *Client) isAuthKubernetesMounted() (bool, error) {

	path := "sys/auth"
	response := struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}{}

	jsonRequest, err := c.newJsonRequest(http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}

	logger.Logf("checking if auth kubernetes is mounted: GET %s", path)
	errorHandlers := []errorHandler{permissionDeniedErrorHandler}
	if err := c.doJsonRequest(jsonRequest, &response, errorHandlers, httpNumberOfRetries); err != nil {
		return false, err
	}

	for key, val := range response.Data {
		if strings.Trim(key, "/") == c.mount {
			if val.Type != kubernetesMountType {
				return false, fmt.Errorf("found %s auth backend but with incorrect type %s", key, val.Type)
			}
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) newJsonRequest(method, path string, jsonRequestBody interface{}) (*http.Request, error) {

	var body io.Reader
	if jsonRequestBody != nil {
		requestBody, err := json.Marshal(jsonRequestBody)
		if err != nil {
			return nil, fmt.Errorf("marshal json request: %w", err)
		}
		body = bytes.NewBuffer(requestBody)
	}

	url := c.buildVaultUrl(path)
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("new http request: %w", err)
	}

	request.Header.Add("Content-Type", "application/json")
	return request, nil
}

// http request, request and response body can be nil, retries is number of retries if request fails,
// it is advisable to specify 2 or more retries, in case token expires we can retry with newly generated token
func (c *Client) doJsonRequest(request *http.Request, jsonResponseBody interface{}, errorHandlers []errorHandler, retries int) error {

	if retries == 0 {
		return errors.New("number of retries exceeded")
	}

	request.Header.Set("X-Vault-Token", c.token)
	responseErrs, err := c.doHttpRequest(request, jsonResponseBody)
	if err != nil {
		logger.Errorf("%v: remaining retries %d", err, retries)
		return c.doJsonRequest(request, jsonResponseBody, errorHandlers, retries-1)
	}

	if responseErrs != nil {
		for _, handler := range errorHandlers {
			stop, err := handler(c, responseErrs, jsonResponseBody, retries)
			if stop || err != nil {
				return err
			}
		}
		logger.Errorf("response errors: %s: remaining retries %d", responseErrs, retries)
		return c.doJsonRequest(request, jsonResponseBody, errorHandlers, retries-1)
	}
	return nil
}

func (c *Client) doHttpRequest(request *http.Request, jsonResponseBody interface{}) (*responseErrors, error) {

	response, err := c.config.HttpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("http httpClient do: %w", err)
	}

	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if response.StatusCode/100 != 2 {
		var errs = struct {
			Errors []string `json:"errors"`
		}{}
		if len(responseBody) > 0 {
			if err := json.Unmarshal(responseBody, &errs); err != nil {
				return nil, fmt.Errorf("unmarshal json response: %w", err)
			}
		}
		return &responseErrors{status: response.StatusCode, errors: errs.Errors}, nil
	}

	if jsonResponseBody != nil {
		if err := json.Unmarshal(responseBody, jsonResponseBody); err != nil {
			return nil, fmt.Errorf("unmarshal json response: %w", err)
		}
	}
	return nil, nil
}

// helper method to authenticate first time or regenerate token if it is expired, do not call this method
// directly it is used automatically by 'jsonRequest' when retries argument is set to 2 or higher
func (c *Client) appRoleLogin(retries int) error {

	path := "auth/approle/login"
	request := struct {
		RoleId   string `json:"role_id"`
		SecretId string `json:"secret_id"`
	}{
		RoleId:   c.config.RoleId,
		SecretId: c.config.SecretId,
	}
	response := struct {
		Auth struct {
			Renewable     bool     `json:"renewable"`
			LeaseDuration int      `json:"lease_duration"`
			TokenPolicies []string `json:"token_policies"`
			Accessor      string   `json:"accessor"`
			ClientToken   string   `json:"client_token"`
		} `json:"auth"`
	}{}

	jsonRequest, err := c.newJsonRequest(http.MethodPost, path, request)
	if err != nil {
		return err
	}
	if err := c.doJsonRequest(jsonRequest, &response, nil, retries); err != nil {
		return err
	}

	logger.Logf("app role login: renewable %t, lease duration %d, token policies %v",
		response.Auth.Renewable, response.Auth.LeaseDuration, response.Auth.TokenPolicies)
	c.token = response.Auth.ClientToken
	return nil
}

func (c *Client) buildVaultUrl(path string) string {

	// trim last '/', vault returns 400 (Bad Request) if url ends with '/'
	return fmt.Sprintf("%s/%s/%s", c.config.Host, vaultVersion, strings.Trim(path, "/"))
}
