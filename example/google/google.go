package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/zalando/gin-oauth2/google"
	goauth "google.golang.org/api/oauth2/v2"
)

var redirectURL, credFile string

func init() {
	bin := path.Base(os.Args[0])
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage of %s
================
`, bin)
		flag.PrintDefaults()
	}
	flag.StringVar(&redirectURL, "redirect", "http://127.0.0.1:8081/auth/", "URL to be redirected to after authorization.")
	flag.StringVar(&credFile, "cred-file", "./example/google/test-clientid.google.json", "Credential JSON file")
}
func main() {
	flag.Parse()

	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.email",
		// You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
	}
	secret := []byte("secret")
	sessionName := "goquestsession"

	router := fiber.New()
	router.Use(logger.New())
	router.Use(recover.New())
	// init settings for google auth
	google.Setup(redirectURL, credFile, scopes, secret)
	router.Use(google.Session(sessionName))

	router.Get("/login", google.LoginHandler)

	// protected url group
	private := router.Group("/auth")
	private.Use(google.Auth())
	private.Get("/", UserInfoHandler)
	private.Get("/api", func(ctx *fiber.Ctx) error {
		return ctx.JSON(fiber.Map{"message": "Hello from private for groups"})
	})

	router.Listen("127.0.0.1:8081")
}

func UserInfoHandler(ctx *fiber.Ctx) error {
	var (
		res goauth.Userinfo
		ok  bool
	)

	val := ctx.Locals("user")
	if res, ok = val.(goauth.Userinfo); !ok {
		res = goauth.Userinfo{Name: "no user"}
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{"Hello": "from private", "user": res.Email})
}
