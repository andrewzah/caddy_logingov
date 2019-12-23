package caddy_logingov

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

const COOKIE_STATE = "LoginGovOAuthState"
const COOKIE_CODE = "LoginGovOAuthCode"
const COOKIE_USER_STORE = "LoginGovOAuthUserStore"

type UserStore struct {
	Sub       string `json:"sub"`
	Iss       string `json:"iss"`
	Email     string `json:"email"`
	Token     string `json:"id_token"`
	ExpiresIn int64  `json:"expires_in"`
}

func newUserStore(tr *TokenResponse, ui *UserInfo) UserStore {
	return UserStore{
		Sub:       ui.Sub,
		Iss:       ui.Iss,
		Email:     ui.Email,
		ExpiresIn: tr.ExpiresIn,
		Token:     tr.IdToken,
	}
}

// response from userinfo endpoint
type UserInfo struct {
	Sub           string `json:"sub"`
	Iss           string `json:"iss"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// response from token endpoint
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type LoginGovHandler struct {
	c      Config
	Next   httpserver.Handler
	client http.Client
}

const contentTypeHTML = "text/html; charset=utf-8"
const contentTypeJWT = "application/jwt"
const contentTypeJSON = "application/json"
const contentTypePlain = "text/plain"

func (h *LoginGovHandler) makeAuthURL(state, codeChallenge string) (string, error) {
	nonce, err := randomHex(32)
	if err != nil {
		return nonce, err
	}

	var buf bytes.Buffer
	buf.WriteString(h.c.Endpoint.AuthURL + "?")
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {h.c.ClientID},
		"scope":                 {h.c.Scopes},
		"redirect_uri":          {h.c.RedirectURL},
		"acr_values":            {h.c.AcrValues},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	buf.WriteString(v.Encode())
	return buf.String(), nil
}

func (h *LoginGovHandler) makeTokenURL(code, codeVerifier string) (string, error) {
	return "", nil
}

func (h LoginGovHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	switch {
	case httpserver.Path(r.URL.Path).Matches(h.c.CallbackPath):
		return h.serveCallback(w, r)
	case h.c.LogoutURL != "" && httpserver.Path(r.URL.Path).Matches(h.c.LogoutURL):
		return h.serveLogout(w, r)
	default:
		return h.serveHTTP(w, r)
	}
}

func getUserStoreFromCookie(r *http.Request) (UserStore, error) {
	val, err := getCookie(r, COOKIE_USER_STORE)
	if err != nil {
		return UserStore{}, err
	}
	userStore := UserStore{}
	err = json.Unmarshal([]byte(val), &userStore)
	if err != nil {
		return UserStore{}, err
	}

	return userStore, nil
}

func (h LoginGovHandler) serveHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if httpserver.Path(r.URL.Path).Matches(h.c.LoginURL) {
		return h.serveLogin(w, r)
	}

	userStore, _ := getUserStoreFromCookie(r)

	for _, path := range h.c.AuthPaths {
		serverPath := httpserver.Path(r.URL.Path)
		if stringInSlice(string(serverPath), h.c.WhitelistPaths) || !serverPath.Matches(path) {
			continue
		}

		if userStore == (UserStore{}) {
			cookie := &http.Cookie{
				Name:  "origin",
				Value: r.URL.String(),
				Path:  "/",
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, h.c.LoginURL, http.StatusTemporaryRedirect)
			return http.StatusTemporaryRedirect, nil
		}

		if !h.c.Emails[userStore.Email] {
			fmt.Printf("[LoginGov] (403) Email not authorized: %s\n", userStore.Email)
			return 403, errors.New("Email not authorized!")
		}
	}

	return h.Next.ServeHTTP(w, r)
}

func (h LoginGovHandler) serveLogin(w http.ResponseWriter, r *http.Request) (int, error) {
	state, err := randomHex(32)
	if err != nil {
		return 500, err
	}

	codeVerifier, codeChallenge, err := genCodeChallenge(32)
	if err != nil {
		return 500, err
	}

	authURL, err := h.makeAuthURL(state, codeChallenge)
	if err != nil {
		return 500, err
	}

	setCookie(w, COOKIE_STATE, state)
	setCookie(w, COOKIE_CODE, codeVerifier)

	http.Redirect(w, r, authURL, 303)
	return 200, nil
}

// receiving a GET after POSTing to auth
// <redir_path>?code=<code>&state=<state>
func (h LoginGovHandler) serveCallback(w http.ResponseWriter, r *http.Request) (int, error) {
	code, ok := r.URL.Query()["code"]
	if !ok {
		err, _ := r.URL.Query()["error"]
		msg := fmt.Sprintf("[LoginGov] Auth response error: %s", err[0])
		fmt.Printf(msg)
		return 500, errors.New(msg)
	}
	state, ok := r.URL.Query()["state"]
	if !ok || len(state[0]) < 1 {
		fmt.Printf("[LoginGov] state parameter was not supplied")
		return 500, errors.New("state parameter was not supplied")
	}

	original_state, err := getCookie(r, COOKIE_STATE)
	if err != nil {
		fmt.Printf("[LoginGov] Cookie for oauth state not found: %v", err)
		return 500, errors.New("err: %v")
	}

	codeVerifier, err := getCookie(r, COOKIE_CODE)
	if err != nil {
		fmt.Printf("[LoginGov] Cookie for oauth code not found: %v", err)
		return 500, errors.New("err: %v")
	}

	if original_state != state[0] {
		fmt.Printf("[LoginGov] FATAL! Original state and received state don't match!!")
		return 500, errors.New("FATAL! Original state and received state don't match!!")
	}

	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
		"code":          {code[0]},
	}

	resp, err := http.PostForm(h.c.Endpoint.TokenURL, v)
	if err != nil {
		return 500, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 500, err
	}

	var tokenResponse = new(TokenResponse)
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return 500, err
	}

	req, err := http.NewRequest("GET", h.c.Endpoint.UserInfoURL, nil)
	authorization := fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken)
	req.Header.Add("Authorization", authorization)

	resp, err = h.client.Do(req)
	if err != nil {
		return 500, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)

	var userInfo = new(UserInfo)
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return 500, err
	}

	userStore := newUserStore(tokenResponse, userInfo)
	json, _ := json.Marshal(userStore)
	setCookie(w, COOKIE_USER_STORE, string(json))

	fmt.Printf("[LoginGov] Successfully signed in with user %s\n", userStore.Email)
	http.Redirect(w, r, "/", 303)
	return h.Next.ServeHTTP(w, r)
}

func (h LoginGovHandler) serveLogout(w http.ResponseWriter, r *http.Request) (int, error) {
	deleteCookie(w, COOKIE_STATE)
	deleteCookie(w, COOKIE_CODE)
	deleteCookie(w, COOKIE_USER_STORE)
	return h.Next.ServeHTTP(w, r)
}
