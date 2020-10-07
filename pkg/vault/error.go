package vault

import (
	"fmt"
	"github.com/pete911/vault-auth-kubernetes/logger"
	"strings"
)

type errorHandler func(c *Client, responseErrs *responseErrors, jsonResponseBody interface{}, retries int) (stop bool, err error)

// error handler that handles 404 as success, some LIST methods will return 404 e.g roles if there are not roles yet
func expectedNotFoundErrorHandler(c *Client, responseErrs *responseErrors, jsonResponseBody interface{}, retries int) (bool, error) {

	if responseErrs.status == 404 {
		jsonResponseBody = nil
		return true, nil
	}
	return false, nil
}

func permissionDeniedErrorHandler(c *Client, responseErrs *responseErrors, _ interface{}, retries int) (bool, error) {

	if responseErrs.contains("permission denied") {
		logger.Error("permission denied: re-generating token")
		if err := c.appRoleLogin(retries - 1); err != nil {
			return true, fmt.Errorf("app role login: %w", err)
		}
	}
	return false, nil
}

type responseErrors struct {
	status int
	errors []string
}

func (r *responseErrors) contains(msg string) bool {

	for _, line := range r.errors {
		if line == msg {
			return true
		}
	}
	return false
}

func (r *responseErrors) String() string {

	errs := strings.Join(r.errors, ", ")
	errs = strings.ReplaceAll(errs, "\t", "")
	errs = strings.ReplaceAll(errs, "\n", "")
	return fmt.Sprintf("%d %q", r.status, errs)
}
