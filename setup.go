package caddy_logingov

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}

func newLoginGovEndpoint() Endpoint {
	return Endpoint{
		AuthURL:     "https://idp.int.identitysandbox.gov/openid_connect/authorize",
		TokenURL:    "https://idp.int.identitysandbox.gov/api/openid_connect/token",
		UserInfoURL: "https://idp.int.identitysandbox.gov/api/openid_connect/userinfo",
	}
}

func init() {
	caddy.RegisterPlugin("logingov", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	conf, err := parse(c)
	if err != nil {
		fmt.Printf("caddy_oauth plugin is initiated with conf=%#v\n", conf)
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("caddy_logingov middleware initiated")
		return nil
	})

	c.OnShutdown(func() error {
		fmt.Println("caddy_logingov plugin is cleaning up")
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return LoginGovHandler{
			Next:   next,
			c:      conf,
			client: http.Client{},
		}
	})

	return nil
}
