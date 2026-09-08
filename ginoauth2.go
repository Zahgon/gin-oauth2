// Package ginoauth2 implements an OAuth2 based authorization
// middleware for the Fiber https://github.com/gofiber/fiber
// webframework.
//
// Example:
//
//	package main
//	import (
//		"flag"
//		"time"
//		"github.com/gofiber/fiber/v2"
//		"github.com/gofiber/fiber/v2/middleware/logger"
//		"github.com/gofiber/fiber/v2/middleware/recover"
//		"github.com/golang/glog"
//		"github.com/zalando/gin-oauth2"
//		"golang.org/x/oauth2"
//	)
//
//	var OAuth2Endpoint = oauth2.Endpoint{
//		AuthURL:  "https://token.oauth2.corp.com/access_token",
//		TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	}
//
//	func UidCheck(tc *TokenContainer, ctx *fiber.Ctx) bool {
//	 uid := tc.Scopes["uid"].(string)
//	 if uid != "sszuecs" {
//	  return false
//	 }
//	 ctx.Locals("uid", uid)
//	 return true
//	}
//
//	func main() {
//		flag.Parse()
//		router := fiber.New()
//		router.Use(logger.New())
//		router.Use(recover.New())
//
//		ginoauth2.VarianceTimer = 300 * time.Millisecond // defaults to 30s
//
//		public := router.Group("/api")
//		public.Get("/", func(c *fiber.Ctx) error {
//			return c.JSON(fiber.Map{"message": "Hello to public world"})
//		})
//
//		private := router.Group("/api/private")
//		private.Use(ginoauth2.Auth(UidCheck, OAuth2Endpoint))
//		private.Get("/", func(c *fiber.Ctx) error {
//			return c.JSON(fiber.Map{"message": "Hello from private"})
//		})
//
//		glog.Info("bootstrapped application")
//		router.Listen(":8081")
package ginoauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// VarianceTimer controls the max runtime of Auth() and AuthChain() middleware
var VarianceTimer time.Duration = 30000 * time.Millisecond

// AuthInfoURL is the URL to get information of your token
var AuthInfoURL string

// Transport to use for client http connections to AuthInfoURL
var Transport = http.Transport{}

// TokenContainer stores all relevant token information
type TokenContainer struct {
	Token     *oauth2.Token
	Scopes    map[string]interface{} // LDAP record vom Benutzer (cn, ..
	GrantType string                 // password, ??
	Realm     string                 // services, employees
}

// AccessCheckFunction is a function that checks if a given token grants
// access.
type AccessCheckFunction func(tc *TokenContainer, ctx *fiber.Ctx) bool

type Options struct {
	Endpoint            oauth2.Endpoint
	AccessTokenInHeader bool
}

var accessTokenMask = regexp.MustCompile("[?&]access_token=[^&]+")

func maskAccessToken(a interface{}) string {
	s := fmt.Sprint(a)
	s = accessTokenMask.ReplaceAllString(s, "<MASK>")
	return s
}

func extractToken(ctx *fiber.Ctx) (*oauth2.Token, error) {
	hdr := ctx.Get(fiber.HeaderAuthorization)
	if hdr == "" {
		return nil, errors.New("no authorization header")
	}

	typ, token, ok := strings.Cut(hdr, " ")
	if !ok {
		return nil, errors.New("invalid authorization header")
	}
	return &oauth2.Token{AccessToken: token, TokenType: typ}, nil
}

func requestAuthInfo(o Options, t *oauth2.Token) ([]byte, error) {
	var infoURL string
	if o.AccessTokenInHeader {
		infoURL = AuthInfoURL
	} else {
		var uv = make(url.Values)
		uv.Set("access_token", t.AccessToken)
		infoURL = AuthInfoURL + "?" + uv.Encode()
	}

	client := &http.Client{Transport: &Transport}
	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return nil, err
	}

	if o.AccessTokenInHeader {
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func RequestAuthInfo(t *oauth2.Token) ([]byte, error) {
	return requestAuthInfo(Options{}, t)
}

func ParseTokenContainer(t *oauth2.Token, data map[string]interface{}) (*TokenContainer, error) {
	tdata := make(map[string]interface{})

	ttype := data["token_type"].(string)
	gtype := data["grant_type"].(string)

	realm := data["realm"].(string)
	exp := data["expires_in"].(float64)
	tok := data["access_token"].(string)
	if ttype != t.TokenType {
		return nil, errors.New("token type mismatch")
	}
	if tok != t.AccessToken {
		return nil, errors.New("mismatch between verify request and answer")
	}

	scopes := data["scope"].([]interface{})
	for _, scope := range scopes {
		sscope := scope.(string)
		sval, ok := data[sscope]
		if ok {
			tdata[sscope] = sval
		}
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: tok,
			TokenType:   ttype,
			Expiry:      time.Now().Add(time.Duration(exp) * time.Second),
		},
		Scopes:    tdata,
		Realm:     realm,
		GrantType: gtype,
	}, nil
}

func getTokenContainerForToken(o Options, token *oauth2.Token) (*TokenContainer, error) {
	body, err := requestAuthInfo(o, token)
	if err != nil {
		errorf("[Gin-OAuth] RequestAuthInfo failed caused by: %s", err)
		return nil, err
	}
	// extract AuthInfo
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		errorf("[Gin-OAuth] JSON.Unmarshal failed caused by: %s", err)
		return nil, err
	}
	if si, ok := data["error_description"]; ok {
		s, ok := si.(string)
		if !ok {
			s = ""
		}
		errorf("[Gin-OAuth] RequestAuthInfo returned an error: %s", s)
		return nil, errors.New(s)
	}
	return ParseTokenContainer(token, data)
}

func GetTokenContainer(token *oauth2.Token) (*TokenContainer, error) {
	return getTokenContainerForToken(Options{}, token)
}

// denyUnauthenticated answers a request that carries no usable token.
func denyUnauthenticated(ctx *fiber.Ctx, o Options, start time.Time, reason string) error {
	// set LOCATION header to auth endpoint such that the user can easily get a new access-token
	ctx.Set(fiber.HeaderLocation, o.Endpoint.AuthURL)
	infofv2("[Gin-OAuth] %12v %s access not allowed", time.Since(start), ctx.Path())

	return fiber.NewError(http.StatusUnauthorized, reason)
}

// denyOvertime answers a request whose authorization check did not finish
// within VarianceTimer.
func denyOvertime(ctx *fiber.Ctx, start time.Time) error {
	infofv2("[Gin-OAuth] %12v %s overtime", time.Since(start), ctx.Path())

	return fiber.NewError(http.StatusGatewayTimeout, "authorization check overtime")
}

// Valid validates that the AccessToken within TokenContainer is not
// expired and not empty.
func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

// Auth implements a router middleware that can be used to get an
// authenticated and authorized service for the whole router group.
// Example:
//
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := fiber.New()
//		private := router.Group("")
//		private.Use(ginoauth2.Auth(ginoauth2.UidCheck, ginoauth2.endpoints))
//		private.Get("/api/private", func(c *fiber.Ctx) error {
//			return c.JSON(fiber.Map{"message": "Hello from private"})
//		})
func Auth(accessCheckFunction AccessCheckFunction, endpoints oauth2.Endpoint) fiber.Handler {
	return AuthChain(endpoints, accessCheckFunction)
}

// AuthChain is a router middleware that can be used to get an authenticated
// and authorized service for the whole router group. Similar to Auth, but
// takes a chain of AccessCheckFunctions and only fails if all of them fails.
// Example:
//
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := fiber.New()
//		    private := router.Group("")
//	     checkChain := []AccessCheckFunction{
//	         ginoauth2.UidCheck,
//	         ginoauth2.GroupCheck,
//	     }
//	     private.Use(ginoauth2.AuthChain(checkChain, ginoauth2.endpoints))
//	     private.Get("/api/private", func(c *fiber.Ctx) error {
//	         return c.JSON(fiber.Map{"message": "Hello from private"})
//	     })
func AuthChain(endpoint oauth2.Endpoint, accessCheckFunctions ...AccessCheckFunction) fiber.Handler {
	return AuthChainOptions(Options{Endpoint: endpoint}, accessCheckFunctions...)
}

func AuthChainOptions(o Options, accessCheckFunctions ...AccessCheckFunction) fiber.Handler {
	// init
	AuthInfoURL = o.Endpoint.TokenURL
	// middleware
	return func(ctx *fiber.Ctx) error {
		t := time.Now()

		// Fiber hands the request context back to its pool as soon as
		// the handler returns, so nothing that may outlive the handler
		// is allowed to touch ctx. The token is therefore read from the
		// request up front and the access checks are run in this
		// goroutine; only the token info request, which is the call
		// that can block on a remote service, runs concurrently to the
		// VarianceTimer.
		oauthToken, err := extractToken(ctx)
		if err != nil {
			errorf("[Gin-OAuth] Can not extract oauth2.Token, caused by: %s", err)
			return denyUnauthenticated(ctx, o, t, "no token in context")
		}

		if !oauthToken.Valid() {
			infof("[Gin-OAuth] Invalid Token - nil or expired")
			return denyUnauthenticated(ctx, o, t, "no token in context")
		}

		varianceControl := make(chan *TokenContainer, 1)
		go func() {
			tc, err := getTokenContainerForToken(o, oauthToken)
			if err != nil {
				errorf("[Gin-OAuth] Can not extract TokenContainer, caused by: %s", err)
				varianceControl <- nil
				return
			}
			varianceControl <- tc
		}()

		var tokenContainer *TokenContainer
		select {
		case tokenContainer = <-varianceControl:
			if tokenContainer == nil {
				return denyUnauthenticated(ctx, o, t, "no token in context")
			}
		case <-time.After(VarianceTimer):
			return denyOvertime(ctx, t)
		}

		if !tokenContainer.Valid() {
			return denyUnauthenticated(ctx, o, t, "invalid Token")
		}

		deadline := t.Add(VarianceTimer)
		for i, fn := range accessCheckFunctions {
			if time.Now().After(deadline) {
				return denyOvertime(ctx, t)
			}

			if fn(tokenContainer, ctx) {
				infofv2("[Gin-OAuth] %12v %s access allowed", time.Since(t), ctx.Path())

				return ctx.Next()
			}

			if len(accessCheckFunctions)-1 == i {
				infofv2("[Gin-OAuth] %12v %s access not allowed", time.Since(t), ctx.Path())

				return fiber.NewError(http.StatusForbidden, "access to the Resource is forbidden")
			}
		}

		// without a single access check function there is nothing that
		// can grant access, which the Gin implementation reported as an
		// authorization check that ran into the VarianceTimer
		return denyOvertime(ctx, t)
	}
}

// RequestLogger is a middleware that logs all the request and prints
// relevant information.  This can be used for logging all the
// requests that contain important information and are authorized.
// The assumption is that the request to log has a content and an Id
// identifiying who made the request uIdKey string to use as key to
// get the uid from the context contentKey string to use as key to get
// the content to be logged from the context.
//
// Example:
//
//	     var endpoints oauth2.Endpoint = oauth2.Endpoint{
//		        AuthURL:  "https://token.oauth2.corp.com/access_token",
//		        TokenURL: "https://oauth2.corp.com/corp/oauth2/tokeninfo",
//	     }
//	     var acl []ginoauth2.AccessTuple = []ginoauth2.AccessTuple{{"employee", 1070, "sszuecs"}, {"employee", 1114, "njuettner"}}
//	     router := fiber.New()
//	     router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
func RequestLogger(keys []string, contentKey string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()
		err := c.Next()
		if method != "GET" && err == nil {
			if data := c.Locals(contentKey); data == nil {
				values := make([]string, 0)
				for _, key := range keys {
					val := c.Locals(key)
					if val != nil {
						values = append(values, val.(string))
					}
				}
				infof("[Gin-OAuth] Request: %+v for %s", data, strings.Join(values, "-"))
			}
		}
		return err
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
