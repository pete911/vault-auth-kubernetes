package vault

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	testHttpClient = &http.Client{Timeout: 10 * time.Second}
	authK8sMount   = "kubernetes/hcom-sandbox-aws/backend"
)

func TestNewClient(t *testing.T) {

	t.Run("when new client has successfully logged in then token is set", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/approle/login" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(authAppRoleResponse))
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		c, err := NewClient(Config{HttpClient: testHttpClient, Host: testServer.URL}, authK8sMount)
		require.NoError(t, err)

		assert.Equal(t, "5b1a0318-679c-9c45-e5c6-d1b9a9035d49", c.token)
	})

	t.Run("when new client login fails then login is retried", func(t *testing.T) {

		var requestNumber int
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			requestNumber++
			if req.URL.Path == "/v1/auth/approle/login" && req.Method == http.MethodPost {
				if requestNumber == 2 {
					res.WriteHeader(http.StatusOK)
					res.Write([]byte(authAppRoleResponse))
					return
				}
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		c, err := NewClient(Config{HttpClient: testHttpClient, Host: testServer.URL}, authK8sMount)
		require.NoError(t, err)

		assert.Equal(t, "5b1a0318-679c-9c45-e5c6-d1b9a9035d49", c.token)
	})

	t.Run("when new client login keeps fails then error returned to avoid infinite loop", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		_, err := NewClient(Config{HttpClient: testHttpClient, Host: testServer.URL}, authK8sMount)
		require.Error(t, err)
	})
}

func TestClient_InitAuthKubernetes(t *testing.T) {

	t.Run("when auth is already mounted then init is skipped and no error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusOK)
			res.Write([]byte(listAuthMethodsResponse))
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.NoError(t, err)
	})

	t.Run("when list auth mounts request fails then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.Error(t, err)
	})

	t.Run("when auth is already mounted but with different type then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusOK)
			res.Write([]byte(listAuthMethodsResponseWithUnexpectedAuthType))
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.Error(t, err)
	})

	t.Run("when auth is not mounted then it is initialised - mounted and configured", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/sys/auth" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(`{}`)) // no mounts returned, meaning that nothing is mounted
				return
			}
			if req.URL.Path == "/v1/sys/auth/kubernetes/hcom-sandbox-aws/backend" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				return
			}
			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/config" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.NoError(t, err)
	})

	t.Run("when auth is not mounted and mounting fails then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/sys/auth" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(`{}`)) // no mounts returned, meaning that nothing is mounted
				return
			}
			if req.URL.Path == "/v1/sys/auth/kubernetes/hcom-sandbox-aws/backend" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusInternalServerError)
				return
			}
			res.WriteHeader(http.StatusOK)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.Error(t, err)
	})

	t.Run("when auth is not mounted and configuration fails then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/sys/auth" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(`{}`)) // no mounts returned, meaning that nothing is mounted
				return
			}
			if req.URL.Path == "/v1/sys/auth/kubernetes/hcom-sandbox-aws/backend" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				return
			}
			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/config" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusInternalServerError)
				return
			}
			res.WriteHeader(http.StatusOK)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.InitAuthKubernetes("https://backend.kube.com", []byte("CA"), []byte("JWT"))
		require.Error(t, err)
	})
}

func TestClient_DeleteAuthKubernetes(t *testing.T) {

	t.Run("when auth is mounted then it is deleted and no error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/sys/auth" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(listAuthMethodsResponse))
				return
			}
			if req.URL.Path == "/v1/sys/auth/kubernetes/hcom-sandbox-aws/backend" && req.Method == http.MethodDelete {
				res.WriteHeader(http.StatusOK)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteAuthKubernetes()
		require.NoError(t, err)
	})

	t.Run("when auth is not mounted then delete is skipped and no error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusOK)
			res.Write([]byte(`{}`)) // no mounts returned, meaning that nothing is mounted
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteAuthKubernetes()
		require.NoError(t, err)
	})

	t.Run("when list auth mounts request fails then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteAuthKubernetes()
		require.Error(t, err)
	})

	t.Run("when auth is already mounted but with different type then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			assert.Equal(t, "/v1/sys/auth", req.URL.Path)
			assert.Equal(t, "ABC123", req.Header.Get("X-Vault-Token"))

			res.WriteHeader(http.StatusOK)
			res.Write([]byte(listAuthMethodsResponseWithUnexpectedAuthType))
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteAuthKubernetes()
		require.Error(t, err)
	})
}

func TestClient_jsonRequest(t *testing.T) {

	t.Run("when request keeps failing then we fail after retries are exceeded to avoid infinite loop", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(`{"errors":["internal server error"]}`))
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		_, err := v.isAuthKubernetesMounted()
		require.Error(t, err)
	})

	t.Run("when token is expired then login needs to happen to re-generate token before the request", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/approle/login" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(authAppRoleResponse))
				return
			}
			if req.URL.Path == "/v1/sys/auth" && req.Method == http.MethodGet {
				if req.Header.Get("X-Vault-Token") == "expired-token" {
					res.WriteHeader(http.StatusForbidden)
					res.Write([]byte(`{"errors":["permission denied"]}`))
					return
				}
				assert.Equal(t, "5b1a0318-679c-9c45-e5c6-d1b9a9035d49", req.Header.Get("X-Vault-Token"))
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(listAuthMethodsResponse))
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "expired-token",
		}

		_, err := v.isAuthKubernetesMounted()
		require.NoError(t, err)
	})

	t.Run("when malformed json is received then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/approle/login" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(`} malformed json {`))
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
		}
		err := v.appRoleLogin(2)
		require.Error(t, err)
	})
}

func TestClient_CreateRole(t *testing.T) {

	t.Run("when create role is successful then no error is returned", func(t *testing.T) {

		var called int
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			called = called + 1
			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test2" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusNotFound)
				return
			}

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test2" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.CreateRole("test2", Role{
			BoundServiceAccountNames:      []string{"vault-agent-injector"},
			BoundServiceAccountNamespaces: []string{"test2"},
			TokenPolicies:                 []string{"test2"},
			TokenTTL:                      3600,
		})
		require.NoError(t, err)
		assert.Equal(t, 2, called)
	})

	t.Run("when create role is called with existing role then no create request is made and no error returned", func(t *testing.T) {

		role := Role{
			BoundServiceAccountNames:      []string{"vault-agent-injector"},
			BoundServiceAccountNamespaces: []string{"test2"},
			TokenPolicies:                 []string{"test2"},
			TokenTTL:                      3600,
		}

		roleJson, err := json.Marshal(role)
		require.NoError(t, err)

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test2" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(fmt.Sprintf(`{"data": %s}`, string(roleJson))))
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err = v.CreateRole("test2", role)
		require.NoError(t, err)
	})

	t.Run("when create role is called with existing role but different fields then it is created and no error returned", func(t *testing.T) {

		role := Role{TokenTTL: 1800}
		roleJson, err := json.Marshal(role)
		require.NoError(t, err)

		var called int
		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			called = called + 1
			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test2" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(fmt.Sprintf(`{"data": %s}`, string(roleJson))))
				return
			}
			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test2" && req.Method == http.MethodPost {
				res.WriteHeader(http.StatusOK)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err = v.CreateRole("test2", Role{TokenTTL: 3600})
		require.NoError(t, err)
		assert.Equal(t, 2, called)
	})
}

func TestClient_DeleteRole(t *testing.T) {

	t.Run("when delete role is successful then no error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test1" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(readRoleResponse))
				return
			}

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test1" && req.Method == http.MethodDelete {
				res.WriteHeader(http.StatusOK)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteRole("test1")
		require.NoError(t, err)
	})

	t.Run("when delete role is called on non-existing role then no delete request is made and no error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role/test1" && req.Method == http.MethodGet {
				res.WriteHeader(http.StatusNotFound)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		err := v.DeleteRole("test1")
		require.NoError(t, err)
	})
}

func TestClient_ListRoles(t *testing.T) {

	t.Run("when list roles is successful then role names are returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role" && req.Method == "LIST" {
				res.WriteHeader(http.StatusOK)
				res.Write([]byte(listRolesResponse))
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := &Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		roles, err := v.ListRoles()
		require.NoError(t, err)

		assert.Equal(t, []string{"test1"}, roles)
	})

	t.Run("when list roles returns 404 then no error and no roles are returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role" && req.Method == "LIST" {
				res.WriteHeader(http.StatusNotFound)
				return
			}
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer func() { testServer.Close() }()

		v := Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		roles, err := v.ListRoles()
		require.NoError(t, err)

		assert.Equal(t, 0, len(roles))
	})

	t.Run("when list roles fails then error is returned", func(t *testing.T) {

		testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

			if req.URL.Path == "/v1/auth/kubernetes/hcom-sandbox-aws/backend/role" && req.Method == "LIST" {
				res.WriteHeader(http.StatusInternalServerError)
				res.Write([]byte(`{"errors":["internal server error"]}`))
				return
			}
			res.WriteHeader(http.StatusOK)
		}))
		defer func() { testServer.Close() }()

		v := Client{
			config: Config{HttpClient: testHttpClient, Host: testServer.URL},
			mount:  authK8sMount,
			token:  "ABC123",
		}

		_, err := v.ListRoles()
		require.Error(t, err)
	})
}

// --- test data ---

var listAuthMethodsResponse = `
{
	"approle/": {
		"accessor": "auth_approle_726fb3e8",
		"config": {
			"default_lease_ttl": 1800,
			"force_no_cache": false,
			"max_lease_ttl": 3600,
			"token_type": "default-service"
		},
		"description": "",
		"external_entropy_access": false,
		"local": false,
		"options": {},
		"seal_wrap": false,
		"type": "approle",
		"uuid": "fd082a20-ccc2-186a-2334-a24627899b64"
	},
	"token/": {
		"accessor": "auth_token_58261b28",
		"config": {
			"default_lease_ttl": 0,
			"force_no_cache": false,
			"max_lease_ttl": 0,
			"token_type": "default-service"
		},
		"description": "token based credentials",
		"external_entropy_access": false,
		"local": false,
		"options": null,
		"seal_wrap": false,
		"type": "token",
		"uuid": "8faad2e5-7e39-46d1-81a3-d2ec2f5f3dd9"
	},
	"kubernetes/hcom-sandbox-aws/backend/": {
		"accessor": "auth_kubernetes_def",
		"config": {
			"default_lease_ttl": 0,
			"force_no_cache": false,
			"max_lease_ttl": 31536000,
			"token_type": "default-service"
		},
		"description": "Kubernetes auth backend for backend cluster in hcom-sandbox-aws account",
		"external_entropy_access": false,
		"local": false,
		"options": {},
		"seal_wrap": false,
		"type": "kubernetes",
		"uuid": "ghi"
	},
	"request_id": "8d653fb7-761a-7007-a1cf-032543839ddf",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"approle/": {
			"accessor": "auth_approle_726fb3e8",
			"config": {
				"default_lease_ttl": 1800,
				"force_no_cache": false,
				"max_lease_ttl": 3600,
				"token_type": "default-service"
			},
			"description": "",
			"external_entropy_access": false,
			"local": false,
			"options": {},
			"seal_wrap": false,
			"type": "approle",
			"uuid": "fd082a20-ccc2-186a-2334-a24627899b64"
		},
		"token/": {
			"accessor": "auth_token_58261b28",
			"config": {
				"default_lease_ttl": 0,
				"force_no_cache": false,
				"max_lease_ttl": 0,
				"token_type": "default-service"
			},
			"description": "token based credentials",
			"external_entropy_access": false,
			"local": false,
			"options": null,
			"seal_wrap": false,
			"type": "token",
			"uuid": "8faad2e5-7e39-46d1-81a3-d2ec2f5f3dd9"
		},
		"kubernetes/hcom-sandbox-aws/backend/": {
			"accessor": "auth_kubernetes_def",
			"config": {
				"default_lease_ttl": 0,
				"force_no_cache": false,
				"max_lease_ttl": 31536000,
				"token_type": "default-service"
			},
			"description": "Kubernetes auth backend for backend cluster in hcom-sandbox-aws account",
			"external_entropy_access": false,
			"local": false,
			"options": {},
			"seal_wrap": false,
			"type": "kubernetes",
			"uuid": "ghi"
		}
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

var listAuthMethodsResponseWithUnexpectedAuthType = `
{
	"data": {
		"kubernetes/hcom-sandbox-aws/backend/": {
			"accessor": "auth_kubernetes_def",
			"config": {
				"default_lease_ttl": 0,
				"force_no_cache": false,
				"max_lease_ttl": 31536000,
				"token_type": "default-service"
			},
			"description": "Kubernetes auth backend for backend cluster in hcom-sandbox-aws account",
			"external_entropy_access": false,
			"local": false,
			"options": {},
			"seal_wrap": false,
		    "type": "ldap",
			"uuid": "ghi"
		}
	},
}`

var authAppRoleResponse = `
{
	"auth": {
		"renewable": true,
		"lease_duration": 1200,
		"metadata": null,
		"token_policies": ["default"],
		"accessor": "fd6c9a00-d2dc-3b11-0be5-af7ae0e1d374",
		"client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"
	},
	"warnings": null,
	"wrap_info": null,
	"data": null,
	"lease_duration": 0,
	"renewable": false,
	"lease_id": ""
}`

var readRoleResponse = `
{
	"request_id": "abc-def",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"bound_service_account_names": [
			"default",
			"test1"
		],
		"bound_service_account_namespaces": [
			"test1"
		],
		"policies": [
			"test1"
		],
		"token_bound_cidrs": [],
		"token_explicit_max_ttl": 0,
		"token_max_ttl": 0,
		"token_no_default_policy": false,
		"token_num_uses": 0,
		"token_period": 0,
		"token_policies": [
			"test1"
		],
		"token_ttl": 3600,
		"token_type": "default",
		"ttl": 3600
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`

var listRolesResponse = `
{
	"request_id": "abc-def",
	"lease_id": "",
	"renewable": false,
	"lease_duration": 0,
	"data": {
		"keys": [
			"test1"
		]
	},
	"wrap_info": null,
	"warnings": null,
	"auth": null
}`
