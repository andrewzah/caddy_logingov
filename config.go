package caddy_logingov

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"golang.org/x/oauth2"
)

type Config struct {
	OauthConf      *oauth2.Config
	CallbackPath   string
	Scopes         string
	ClientID       string
	Endpoint       Endpoint
	AcrValues      string
	LoginURL       string
	LogoutURL      string
	RedirectURL    string
	SuccessURL     string
	Emails         map[string]bool
	AuthPaths      []string
	WhitelistPaths []string
	Next           httpserver.Handler
	client         http.Client
	codeVerifier   string
}

func newConfig() (Config, error) {
	emails, err := loadEmails()
	if err != nil {
		fmt.Println("Unable to load emails!")
		return Config{}, nil
	}

	return Config{
		Endpoint: newLoginGovEndpoint(),
		Emails:   emails,
	}, nil
}

func loadEmails() (map[string]bool, error) {
	content, err := ioutil.ReadFile("./emails.txt")
	if err != nil {
		return make(map[string]bool), err
	}

	emails := strings.Split(string(content), "\n")
	m := make(map[string]bool)
	for _, email := range emails {
		m[email] = true
	}

	return m, nil
}

func parse(c *caddy.Controller) (Config, error) {
	conf, err := newConfig()
	if err != nil {
		fmt.Printf("[LoginGov] Unable to load Config: %v", err)
		return conf, err
	}

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the Config block
			for c.NextBlock() {
				switch c.Val() {
				case "acr_values":
					conf.AcrValues, err = parseOne(c)
				case "redirect_url":
					conf.RedirectURL, err = parseOne(c)
				case "login_url":
					conf.LoginURL, err = parseOne(c)
				case "logout_url":
					conf.LogoutURL, err = parseOne(c)
				case "client_id":
					conf.ClientID, err = parseOne(c)
				case "auth_url":
					conf.Endpoint.AuthURL, err = parseOne(c)
				case "token_url":
					conf.Endpoint.TokenURL, err = parseOne(c)
				case "success_url":
					conf.SuccessURL, err = parseOne(c)
				case "scopes":
					conf.Scopes, err = parseOne(c)
				case "auth_required":
					path, e := parseOne(c)
					if e != nil {
						return conf, e
					}
					conf.AuthPaths = append(conf.AuthPaths, path)
				case "whitelist":
					path, e := parseOne(c)
					if e != nil {
						return conf, e
					}
					conf.WhitelistPaths = append(conf.WhitelistPaths, path)
				}
				if err != nil {
					return conf, err
				}
			}
		default:
			return conf, c.ArgErr()
		}
	}

	if conf.RedirectURL == "" || conf.ClientID == "" || conf.AcrValues == "" {
		return conf, fmt.Errorf("[LoginGov] redirect_url, client_id, and acr_values can't be empty")
	}

	if conf.Scopes == "" {
		conf.Scopes = "email"
	}

	if conf.LoginURL == "" {
		conf.LoginURL = "/login"
	}

	if conf.LogoutURL == "" {
		conf.LogoutURL = "/logout"
	}

	if conf.SuccessURL == "" {
		conf.SuccessURL = "/"
	}

	// callback path
	redirURL, err := url.Parse(conf.RedirectURL)
	if err != nil {
		return conf, err
	}
	conf.CallbackPath = redirURL.Path

	return conf, nil
}

// parse exactly one arguments
func parseOne(c *caddy.Controller) (string, error) {
	if !c.NextArg() {
		// we are expecting a value
		return "Expected one argument.", c.ArgErr()
	}
	val := c.Val()
	if c.NextArg() {
		// we are expecting only one value.
		return "Only expected one argument.", c.ArgErr()
	}
	return val, nil
}

func parseTwo(c *caddy.Controller) (string, string, error) {
	args := c.RemainingArgs()
	if len(args) != 2 {
		return "", "", fmt.Errorf("[LoginGov] expected 2 args, get %v args", len(args))
	}
	return args[0], args[1], nil
}
