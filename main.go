package main

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"going/blazingh/test/initializers"
	"going/blazingh/test/middleware"
	"regexp"
)

type Result struct {
	ID   int
	Name string
}

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDB()
	initializers.LoadConfigFromFile("config.json")
	initializers.LoadCasbinConfig("model.conf", "policy.csv")
}

func isValidTableName(name string) bool {
	// Check if the length is within the allowed limit (adjust as needed)
	if len(name) > 63 {
		return false
	}

	// Check if the name starts with a letter
	match, _ := regexp.MatchString("^[a-zA-Z]", name)
	if !match {
		return false
	}

	// Check if the name consists of alphanumeric characters and underscores
	match, _ = regexp.MatchString("^[a-zA-Z0-9_]*$", name)
	if !match {
		return false
	}

	return true
}

func main() {

	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.GET("/:table", middleware.ValidateToken, func(c *gin.Context) {

		table := c.Param("table")

		if !isValidTableName(table) {
			c.AbortWithStatusJSON(400, "not a valid table name")
		}

		// Access claims from the context
		claims, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(500, "claim was not present")
			return
		}

		// Type-assert the claims to jwt.MapClaims
		claimsMap, ok := claims.(jwt.MapClaims)
		if !ok {
			return
		}

		// Access role item in the claims
		role, roleExists := claimsMap["role"].(string)
		if !roleExists {
			return
		}

		// get smaple data
		tableSample, err := initializers.DB.Table(table).Limit(1).Rows()
		if err != nil {
			c.JSON(500, gin.H{"error": "Error fetching columns"})
			return
		}

		// get the columns of the table
		tableColumns, err := tableSample.Columns()
		if err != nil {
			c.JSON(500, gin.H{"error": "Error fetching columns"})
		}

		// available columns for accessed role
		availableColumns := make([]string, 0)

		// check if the role has access to all the columns
		allAccess, err := initializers.Enforcer.Enforce(role, table, "*", "read")
		if allAccess && err == nil {
			for _, column := range tableColumns {
				availableColumns = append(availableColumns, column)
			}
		} else {
			// check eah column for access
			for _, column := range tableColumns {
				ok, err := initializers.Enforcer.Enforce(role, table, column, "read")
				if ok && err == nil {
					availableColumns = append(availableColumns, column)
				}
			}
		}

		// ahort if ther is no columns to return
		if len(availableColumns) < 1 {
			c.AbortWithStatusJSON(401, "no columns found")
			return
		}

		// get the rows data
		rows, err := initializers.DB.Table(table).Select(availableColumns).Limit(10).Rows()
		if err != nil {
			c.JSON(404, gin.H{"error": "Table " + table + " not found"})
			return
		}
		defer rows.Close()

		// Create a slice to store the values of each row
		var result []map[string]interface{}

		// Fetch each row and store its values in a map
		for rows.Next() {
			// Prepare a slice of pointers to values
			values := make([]interface{}, len(availableColumns))
			for i := range availableColumns {
				values[i] = new(interface{})
			}

			// Scan the row into the slice of pointers
			if err := rows.Scan(values...); err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			// Create a map to store the values of the current row
			rowData := make(map[string]interface{})
			for i, columnName := range availableColumns {
				rowData[columnName] = *(values[i].(*interface{}))
			}

			// Append the map to the result slice
			result = append(result, rowData)
		}

		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}

		// return the result
		c.JSON(200, result)
	})

	r.Run()
}
