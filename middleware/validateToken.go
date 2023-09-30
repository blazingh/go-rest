package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func ValidateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("my_secret_key"), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	if !token.Valid {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized, invalid token"})
		return
	}

	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized, expired token"})
		return
	}

	c.Set("claims", claims)

	c.Next()
}
