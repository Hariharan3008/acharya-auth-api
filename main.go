package main

import (
	"acharya-auth-api/auth"
	"acharya-auth-api/storage"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	
	users := storage.NewUser()
	tokens := storage.NewToken()
	authService := auth.NewAuthService(users, tokens)
	authHandler := auth.NewHandler(authService)

	r := gin.Default()
	
	r.POST("/signup", authHandler.SignUp)
	r.POST("/signin", authHandler.SignIn)
	r.POST("/refresh", authHandler.RefreshToken)
	r.POST("/revoke", authHandler.RevokeToken)
	
	protected := r.Group("/")
	protected.Use(auth.AuthMiddleware(authService))
	{
		protected.GET("/protected", authHandler.ProtectedEndpoint)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(r.Run(":" + port))
}