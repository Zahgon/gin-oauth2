// Package google provides you access to Google's OAuth2
// infrastructure. The implementation is based on this blog post:
// http://skarlso.github.io/2016/06/12/google-signin-with-go/
package google

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/golang/glog"
	goauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

const (
	stateKey  = "state"
	sessionID = "ginoauth_google_session"

	// sessionContextKey is the key the Session() middleware uses to
	// hand the session of the current request over to the handlers.
	sessionContextKey = "ginoauth_google_session_ctx"

	// defaultSessionName is the cookie name used until Session() rebinds
	// the store to an application specific name.
	defaultSessionName = "session_id"
)

var (
	conf  *oauth2.Config
	store *session.Store
)

func init() {
	gob.Register(goauth.Userinfo{})
}

var loginURL string

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v", err)
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
		glog.Fatalf("[Gin-OAuth] File error: %v", err)
	}
	if err := json.Unmarshal(file, &c); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v", err)
	}

	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}
}

// SetupFromString accepts string values for ouath2 Configs
func SetupFromString(redirectURL, clientID string, clientSecret string, scopes []string, secret []byte) {
	store = newStore(defaultSessionName)

	conf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
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
	stateValue := randToken()
	session, err := currentSession(ctx)
	if err != nil {
		return err
	}
	session.Set(stateKey, stateValue)
	session.Save()

	return ctx.Type("html").SendString(`
	<html>
		<head>
			<title>Golang Google</title>
		</head>
	  <body>
			<a href='` + GetLoginURL(stateValue) + `'>
				<button>Login with Google!</button>
			</a>
		</body>
	</html>`)
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func WithLoginURL(s string) error {
	s = strings.TrimSpace(s)
	url, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	loginURL = url.String()
	return nil
}

// Auth is the google authorization middleware. You can use them to protect a routergroup.
// Example:
//
//	       private.Use(google.Auth())
//	       private.Get("/", UserInfoHandler)
//	       private.Get("/api", func(ctx *fiber.Ctx) error {
//	           return ctx.JSON(fiber.Map{"message": "Hello from private for groups"})
//	       })
//
//	   // Requires google oauth pkg to be imported as `goauth "google.golang.org/api/oauth2/v2"`
//	   func UserInfoHandler(ctx *fiber.Ctx) error {
//		      var (
//		      	res goauth.Userinfo
//		      	ok  bool
//		      )
//
//		      val := ctx.Locals("user")
//		      if res, ok = val.(goauth.Userinfo); !ok {
//		      	res = goauth.Userinfo{Name: "no user"}
//		      }
//
//		      return ctx.Status(http.StatusOK).JSON(fiber.Map{"Hello": "from private", "user": res.Email})
//	   }
func Auth() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Handle the exchange code to initiate a transport.
		session, err := currentSession(ctx)
		if err != nil {
			return err
		}

		existingSession := session.Get(sessionID)
		if userInfo, ok := existingSession.(goauth.Userinfo); ok {
			ctx.Locals("user", userInfo)
			return ctx.Next()
		}

		retrievedState := session.Get(stateKey)
		if retrievedState != ctx.Query(stateKey) {
			if loginURL != "" {
				return ctx.Redirect(loginURL, http.StatusFound)
			}
			return fiber.NewError(http.StatusUnauthorized, fmt.Sprintf("invalid session state: %s", retrievedState))
		}

		tok, err := conf.Exchange(context.TODO(), ctx.Query("code"))
		if err != nil {
			return fiber.NewError(http.StatusBadRequest, fmt.Sprintf("failed to exchange code for oauth token: %v", err))
		}

		oAuth2Service, err := goauth.NewService(ctx.UserContext(), option.WithTokenSource(conf.TokenSource(ctx.UserContext(), tok)))
		if err != nil {
			glog.Errorf("[Gin-OAuth] Failed to create oauth service: %v", err)
			return fiber.NewError(http.StatusInternalServerError, fmt.Sprintf("failed to create oauth service: %v", err))
		}

		userInfo, err := oAuth2Service.Userinfo.Get().Do()
		if err != nil {
			glog.Errorf("[Gin-OAuth] Failed to get userinfo for user: %v", err)
			return fiber.NewError(http.StatusInternalServerError, fmt.Sprintf("failed to get userinfo for user: %v", err))
		}

		ctx.Locals("user", userInfo)

		session.Set(sessionID, userInfo)
		if err := session.Save(); err != nil {
			glog.Errorf("[Gin-OAuth] Failed to save session: %v", err)
			return fiber.NewError(http.StatusInternalServerError, fmt.Sprintf("failed to save session: %v", err))
		}

		return ctx.Next()
	}
}
