// Zalando specific example.
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang/glog"
	ginoauth2 "github.com/zalando/gin-oauth2"
	"github.com/zalando/gin-oauth2/zalando"
)

var USERS []zalando.AccessTuple = []zalando.AccessTuple{
	{
		Realm: "/employees",
		Uid: "sszuecs",
		Cn: "Sandor Szücs",
	},
	{
		Realm: "/employees",
		Uid: "njuettner",
		Cn: "Nick Jüttner",
	},
}

var TEAMS []zalando.AccessTuple = []zalando.AccessTuple{
	{
		Realm: "teams",
		Uid: "opensourceguild",
		Cn: "OpenSource",
	},
	{
		Realm: "teams",
		Uid: "tm",
		Cn: "Platform Engineering / System",
	},
	{
		Realm: "teams",
		Uid: "teapot",
		Cn: "Platform / Cloud API",
	},
}
var SERVICES []zalando.AccessTuple = []zalando.AccessTuple{
	{
		Realm: "services",
		Uid: "foo",
		Cn: "Fooservice",
	},
}

func main() {
	flag.Parse()
	router := fiber.New()
	router.Use(logger.New())
	router.Use(ginoauth2.RequestLogger([]string{"uid"}, "data"))
	router.Use(recover.New())

	ginoauth2.VarianceTimer = 300 * time.Millisecond // defaults to 30s

	public := router.Group("/api")
	public.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Hello to public world"})
	})

	private := router.Group("/api/private")
	privateGroup := router.Group("/api/privateGroup")
	privateUser := router.Group("/api/privateUser")
	privateService := router.Group("/api/privateService")
	glog.Infof("Register allowed users: %+v and groups: %+v and services: %+v", USERS, TEAMS, SERVICES)

	private.Use(ginoauth2.AuthChain(zalando.OAuth2Endpoint, zalando.UidCheck(USERS), zalando.GroupCheck(TEAMS), zalando.UidCheck(SERVICES)))
	privateGroup.Use(ginoauth2.Auth(zalando.GroupCheck(TEAMS), zalando.OAuth2Endpoint))
	privateUser.Use(ginoauth2.Auth(zalando.UidCheck(USERS), zalando.OAuth2Endpoint))
	//privateService.Use(ginoauth2.Auth(zalando.UidCheck(SERVICES), zalando.OAuth2Endpoint))
	privateService.Use(ginoauth2.Auth(zalando.ScopeAndCheck("uidcheck", "uid", "bar"), zalando.OAuth2Endpoint))

	private.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Hello from private for groups and users"})
	})
	privateGroup.Get("/", func(c *fiber.Ctx) error {
		uid := c.Locals("uid")
		if team := c.Locals("team"); team != nil && uid != nil {
			return c.JSON(fiber.Map{"message": fmt.Sprintf("Hello from private for groups to %s member of %s", uid, team)})
		} else {
			return c.JSON(fiber.Map{"message": "Hello from private for groups without uid and team"})
		}
	})
	privateUser.Get("/", func(c *fiber.Ctx) error {
		if v := c.Locals("cn"); v != nil {
			return c.JSON(fiber.Map{"message": fmt.Sprintf("Hello from private for users to %s", v)})
		} else {
			return c.JSON(fiber.Map{"message": "Hello from private for users without cn"})
		}
	})
	privateService.Get("/", func(c *fiber.Ctx) error {
		if v := c.Locals("cn"); v != nil {
			return c.JSON(fiber.Map{"message": fmt.Sprintf("Hello from private for services to %s", v)})
		} else {
			return c.JSON(fiber.Map{"message": "Hello from private for services without cn"})
		}
	})

	glog.Info("bootstrapped application")
	router.Listen(":8081")
}
