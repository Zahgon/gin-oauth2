// Package github provides you access to Github's OAuth2
// infrastructure.
package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/golang/glog"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	oauth2gh "golang.org/x/oauth2/github"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

const (
	// sessionContextKey is the key the Session() middleware uses to
	// hand the session of the current request over to the handlers.
	sessionContextKey = "ginoauth_github_session_ctx"

	// defaultSessionName is the cookie name used until Session() rebinds
	// the store to an application specific name.
	defaultSessionName = "session_id"
)

var (
	conf  *oauth2.Config
	state string
	store *session.Store
)

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v\n", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// newStore creates a session store that reads the session id from the
// cookie with the given name.
func newStore(name string) *session.Store {
	return session.New(session.Config{
		KeyLookup:      "cookie:" + name,
		CookieHTTPOnly: true,
	})
}

// currentSession returns the session of the current request. It uses the
// session provided by the Session() middleware, if it was registered.
func currentSession(ctx *fiber.Ctx) (*session.Session, error) {
	if s, ok := ctx.Locals(sessionContextKey).(*session.Session); ok {
		return s, nil
	}
	return store.Get(ctx)
}

// Setup the authorization path.
//
// The secret is kept for API compatibility. Fiber's session middleware
// stores the session data server side and references it by an
// unguessable session id, so no signing secret is required.
func Setup(redirectURL, credFile string, scopes []string, secret []byte) {
	store = newStore(defaultSessionName)
	var c Credentials
	file, err := os.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v\n", err)
	}
	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     oauth2gh.Endpoint,
	}
}

// Session returns a middleware that stores the session identified by the
// cookie name in the request context, such that LoginHandler and Auth can
// use it.
func Session(name string) fiber.Handler {
	store = newStore(name)

	return func(ctx *fiber.Ctx) error {
		sess, err := store.Get(ctx)
		if err != nil {
			return err
		}
		ctx.Locals(sessionContextKey, sess)

		return ctx.Next()
	}
}

func LoginHandler(ctx *fiber.Ctx) error {
	state = randToken()
	session, err := currentSession(ctx)
	if err != nil {
		return err
	}
	session.Set("state", state)
	session.Save()

	return ctx.Type("html").SendString("<html><title>Golang Github</title> <body> <a href='" + GetLoginURL(state) + "'><button>Login with GitHub!</button> </a> </body></html>")
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

type AuthUser struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	URL     string `json:"url"`
}

func init() {
	gob.Register(AuthUser{})
}

func Auth() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		var (
			ok       bool
			authUser AuthUser
			user     *github.User
		)

		// Handle the exchange code to initiate a transport.
		session, err := currentSession(ctx)
		if err != nil {
			return err
		}
		mysession := session.Get("ginoauthgh")
		if authUser, ok = mysession.(AuthUser); ok {
			ctx.Locals("user", authUser)
			return ctx.Next()
		}

		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			return fiber.NewError(http.StatusUnauthorized, fmt.Sprintf("invalid session state: %s", retrievedState))
		}

		stdctx := context.Background()
		tok, err := conf.Exchange(stdctx, ctx.Query("code"))
		if err != nil {
			return fiber.NewError(http.StatusBadRequest, fmt.Sprintf("failed to do exchange: %v", err))
		}
		client := github.NewClient(conf.Client(stdctx, tok))
		user, _, err = client.Users.Get(stdctx, "")
		if err != nil {
			return fiber.NewError(http.StatusBadRequest, fmt.Sprintf("failed to get user: %v", err))
		}
		// Protection: fields used in userinfo might be nil-pointers
		authUser = AuthUser{
			Login: stringFromPointer(user.Login),
			Name:  stringFromPointer(user.Name),
			URL:   stringFromPointer(user.URL),
		}

		// save userinfo, which could be used in Handlers
		ctx.Locals("user", authUser)

		// populate cookie
		session.Set("ginoauthgh", authUser)
		if err := session.Save(); err != nil {
			glog.Errorf("Failed to save session: %v", err)
		}

		return ctx.Next()
	}
}

func stringFromPointer(strPtr *string) (res string) {
	if strPtr == nil {
		res = ""
		return res
	}
	res = *strPtr
	return res
}
