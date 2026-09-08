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
	"github.com/zalando/gin-oauth2/github"
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
	flag.StringVar(&credFile, "cred-file", "./example/github/test-clientid.github.json", "Credential JSON file")
}
func main() {
	flag.Parse()

	scopes := []string{
		"repo",
		// You have to select your own scope from here -> https://developer.github.com/v3/oauth/#scopes
	}
	secret := []byte("secret")
	sessionName := "goquestsession"
	router := fiber.New()
	router.Use(logger.New())
	router.Use(recover.New())
	// init settings for github auth
	github.Setup(redirectURL, credFile, scopes, secret)
	router.Use(github.Session(sessionName))

	router.Get("/login", github.LoginHandler)

	// protected url group
	private := router.Group("/auth")
	private.Use(github.Auth())
	private.Get("/", UserInfoHandler)
	private.Get("/api", func(ctx *fiber.Ctx) error {
		return ctx.JSON(fiber.Map{"message": "Hello from private for groups"})
	})

	router.Listen("127.0.0.1:8081")
}

func UserInfoHandler(ctx *fiber.Ctx) error {
	var (
		res github.AuthUser
		val interface{}
		ok  bool
	)

	val = ctx.Locals("user")
	if res, ok = val.(github.AuthUser); !ok {
		res = github.AuthUser{
			Name: "no User",
		}
	}
	return ctx.Status(http.StatusOK).JSON(fiber.Map{"Hello": "from private", "user": res})
}
