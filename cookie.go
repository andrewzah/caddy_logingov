package caddy_logingov

import (
	b64 "encoding/base64"
	"net/http"
)

func setCookie(w http.ResponseWriter, cookieName, val string) {
	encoded := b64.StdEncoding.EncodeToString([]byte(val))

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		MaxAge:   60 * 60 * 24,
		Value:    encoded,
		HttpOnly: false,
	})
	return
}

func getCookie(r *http.Request, cookieName string) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", err
	}

	decoded, err := b64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func deleteCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		MaxAge:   0,
		Value:    "",
		HttpOnly: false,
	})
	return
}
