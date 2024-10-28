package auth

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// CombinedAuth is a combined implementation of an Auther.
type CombinedAuth struct {
	ProxyHeader string `json:"proxy_header"`
}

// Auth authenticates the user via an HTTP header or falls back to JSON in content body.
func (a CombinedAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	username := r.Header.Get(a.ProxyHeader)
	if username != "" {
		user, err := usr.Get(srv.Root, username)
		if err == nil {
			return user, nil
		}
	}

	var cred jsonCred
	if r.Body == nil {
		return nil, os.ErrPermission
	}

	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		return nil, os.ErrPermission
	}

	u, err := usr.Get(srv.Root, cred.Username)
	if err != nil || !users.CheckPwd(cred.Password, u.Password) {
		return nil, os.ErrPermission
	}

	return u, nil
}

// LoginPage tells that combined auth requires a login page.
func (a CombinedAuth) LoginPage() bool {
	return true
}
