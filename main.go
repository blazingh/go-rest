package main

import (
	"going/blazingh/test/controllers"
	"going/blazingh/test/initializers"
	"going/blazingh/test/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDB()
	initializers.LoadCasbinConfig("model.conf", "policy.csv")
}

func main() {

	r := gin.Default()

	r.GET("/:table", middleware.ValidateToken, controllers.GetTable)

	r.Run()
}
