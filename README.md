# Caddy LoginGov

LoginGov OAuth plugin for [Login.Gov](https://www.login.gov/), as per [these specifications](https://developers.login.gov/oidc/).

**NOTE**: This is not a registered plugin with Caddy, so you need to fork Caddy and build it manually in another project. Add something like this to your project's `go.mod`:

```
module github.com/<your.username>/<your.project>

go 1.13

// for prod
replace github.com/caddyserver/caddy => github.com/<your.username>/caddy master

// for local development
replace github.com/caddyserver/caddy => ../caddy
```

This plugin is for Caddy v1, NOT v2.

## Example

```caddyfile
https://your.website.local {
  tls self_signed

  logingov {
    auth_required /
    auth_required /private
    whitelist /public
    whitelist /public2

    client_id <your id registered with Login.Gov>
    redirect_url https://your.website.local/oauth-callback
    scope email
    acr_values http://idmanagement.gov/ns/assurance/loa/1
    login_url /login
  }
}
```

## License

[MIT](./LICENSE)

## Contributors

* Maintainer - [Andrew Zah <andrew.zah@ossys.com>](https://github.com/azah)

## Sponsor

This project was funded by [OSSYS - Open Source Systems](https://www.ossys.com/).
