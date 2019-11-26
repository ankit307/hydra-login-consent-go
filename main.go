package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	negronilogrus "github.com/meatballhat/negroni-logrus"
	"github.com/ory/common/env"
	"github.com/ory/hydra/sdk/go/hydra/client"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	"github.com/ory/hydra/sdk/go/hydra/models"
	"github.com/pkg/errors"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var store = sessions.NewCookieStore([]byte("something-very-secret-keep-it-safe"))

// The session is a unique session identifier
const sessionName = "authentication"

var c *client.OryHydra

var oauthConf clientcredentials.Config
var clientOauthConfig *oauth2.Config

func main() {
	// Set up a router and some routes
	clientOauthConfig = &oauth2.Config{
		RedirectURL:  "http://127.0.0.1:3001/callback",
		ClientID:     "auth-code-client",
		ClientSecret: "testdemo",
		Scopes:       []string{"openid", "offline"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://127.0.0.1:4444/oauth2/auth",
			TokenURL: "http://127.0.0.1:4444/oauth2/token",
		},
	}
	adminURL, _ := url.Parse("http://hydra.localhost:4445")
	c = client.NewHTTPClientWithConfig(nil, &client.TransportConfig{Schemes: []string{adminURL.Scheme}, Host: adminURL.Host, BasePath: adminURL.Path})
	r := mux.NewRouter()
	r.HandleFunc("/", handleHome)
	r.HandleFunc("/consent", handleConsent)
	r.HandleFunc("/login", handleLogin)
	r.HandleFunc("/callback", handleCallback)
	// Set up a request logger, useful for debugging
	n := negroni.New()
	n.Use(negronilogrus.NewMiddleware())
	n.UseHandler(r)
	// Start http server
	log.Println("Listening on :" + env.Getenv("PORT", "3001"))
	log.Fatal(http.ListenAndServe(":"+env.Getenv("PORT", "3001"), n))
}

// handles request at /home - a small page that let's you know what you can do in this app. Usually the first.
// page a user sees.
func handleHome(w http.ResponseWriter, _ *http.Request) {
	authURL := clientOauthConfig.AuthCodeURL("demotestdemotest")
	renderTemplate(w, "home.html", authURL)
}

// After pressing "click here", the Authorize Code flow is performed and the user is redirected to Hydra. Next, Hydra
// validates the consent request (it's not valid yet) and redirects us to the consent endpoint which we set with `CONSENT_URL=http://localhost:4445/consent`.
func handleConsent(w http.ResponseWriter, r *http.Request) {
	consentRequestID := r.URL.Query().Get("consent_challenge")
	consentRequest, _ := c.Admin.GetConsentRequest(&admin.GetConsentRequestParams{
		ConsentChallenge: consentRequestID,
		// Body: &models.HandledConsentRequest{
		// 	GrantedScope: []string{"offline_access", "offline", "openid"},
		// },
		Context: context.Background(),
	})

	consentRequestAc, _ := c.Admin.AcceptConsentRequest(&admin.AcceptConsentRequestParams{
		ConsentChallenge: consentRequestID,
		Body: &models.HandledConsentRequest{
			GrantedScope: []string{"offline_access", "offline", "openid"},
			Remember:     true,
			RememberFor:  0,
		},
		Context: context.Background(),
	})
	log.Println("consentRequest", consentRequest)
	log.Println("consentRequestAc", consentRequestAc)
	// We received a get request, so let's show the html site where the user may give consent.
	// renderTemplate(w, "consent.html", struct {
	// 	*models.ConsentRequest
	// 	ConsentRequestID string
	// }{ConsentRequest: consentRequest.Payload, ConsentRequestID: consentRequestID})
	http.Redirect(w, r, consentRequestAc.Payload.RedirectTo, http.StatusFound)
	return
}

// The user hits this endpoint if not authenticated. In this example, they can sign in with the credentials
// ankit:test
func handleLogin(w http.ResponseWriter, r *http.Request) {
	consentRequestID := r.URL.Query().Get("login_challenge")
	if r.Method == "POST" {
		consentRequestID := r.URL.Query().Get("consent")
		log.Println("posted Login Form")
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "Could not parse form").Error(), http.StatusBadRequest)
			return
		}
		// Check the user's credentials
		if r.Form.Get("username") != "ankit" || r.Form.Get("password") != "test" {
			http.Error(w, "Provided credentials are wrong, try ankit:test", http.StatusBadRequest)
			return
		}
		session, _ := store.Get(r, sessionName)
		session.Values["user"] = "ankit-test"
		if err := store.Save(r, w, session); err != nil {
			http.Error(w, errors.Wrap(err, "Could not persist cookie").Error(), http.StatusBadRequest)
			return
		}
		log.Printf("consentRequestID %v\n", consentRequestID)
		getLoginReq, _ := c.Admin.GetLoginRequest(&admin.GetLoginRequestParams{
			LoginChallenge: consentRequestID,
			Context:        context.Background(),
		})
		log.Println("getLoginReq", getLoginReq)
		name := "ankit"
		loginRequest, errLog := c.Admin.AcceptLoginRequest(&admin.AcceptLoginRequestParams{
			LoginChallenge: consentRequestID,
			Body: &models.HandledLoginRequest{
				Remember:    false,
				RememberFor: 0,
				Subject:     &name,
			},
			Context: r.Context(),
		})
		log.Println("loginRequest", loginRequest)
		if errLog != nil {
			http.Error(w, errors.Wrap(errLog, "The consent request endpoint does not respond").Error(), http.StatusBadRequest)
			return
		}
		// It's a get request, so let's render the template
		//renderTemplate(w, "login.html", "consentRequestID")
		http.Redirect(w, r, loginRequest.Payload.RedirectTo, http.StatusFound)
		return
	}
	log.Println(consentRequestID)
	// It's a get request, so let's render the template
	renderTemplate(w, "login.html", consentRequestID)
}

// Once the user has given their consent, we will hit this endpoint. Again,
// this is not something that would be included in a traditional consent app,
// but we added it so you can see the data once the consent flow is done.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	oauthConf = clientcredentials.Config{
		ClientID:       "auth-code-client",
		ClientSecret:   "testdemo",
		TokenURL:       "http://127.0.0.1:4444/oauth2/token",
		Scopes:         []string{"openid", "offline"},
		EndpointParams: url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {"http://127.0.0.1:3001/callback"}, "client_id": {"auth-code-client"}, "code": {code}},
	}
	token, err := oauthConf.Token(r.Context())
	if err != nil {
		log.Println("err", err)
	}
	renderTemplate(w, "callback.html", struct {
		*oauth2.Token
		IDToken interface{}
	}{
		Token:   token,
		IDToken: token.Extra("id_token"),
	})
}

// authenticated checks if our cookie store has a user stored and returns the
// user's name, or an empty string if the user is not yet authenticated.
func authenticated(r *http.Request) string {
	session, _ := store.Get(r, sessionName)
	log.Println(session)
	return ""
}

// renderTemplate is a convenience helper for rendering templates.
func renderTemplate(w http.ResponseWriter, id string, d interface{}) bool {
	if t, err := template.New(id).ParseFiles("./templates/" + id); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	} else if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}
