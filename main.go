package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"going/blazingh/test/initializers"
	"going/blazingh/test/middleware"
	"regexp"
	"strconv"
)

type Result struct {
	ID   int
	Name string
}

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDB()
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
			c.AbortWithStatusJSON(500, "claim was not of type jwt.MapClaims")
			return
		}

		// Access role item in the claims
		role, roleExists := claimsMap["role"].(string)
		if !roleExists {
			c.AbortWithStatusJSON(500, "role was not present in the token")
			return
		}

		// get smaple data
		tableSample, err := initializers.DB.Table(table).Limit(1).Rows()
		if err != nil {
			c.AbortWithStatusJSON(500, err.Error())
			return
		}

		// get the columns of the table
		tableColumns, err := tableSample.Columns()
		if err != nil {
			c.AbortWithStatusJSON(500, err.Error())
			return
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

		// abort if there is no columns to return
		if len(availableColumns) < 1 {
			c.AbortWithStatusJSON(401, "no columns found")
			return
		}

		// initialize the query
		queryDB := initializers.DB.Table(table).Select(availableColumns).Limit(10)

		// get the row level policy
		rls := initializers.Enforcer.GetFilteredNamedPolicy("p2", 0, role, table)

		// check for row level security
		if len(rls) > 0 {
			tokenAtr, tokenAtrExists := claimsMap[rls[0][2]].(string)
			if !tokenAtrExists {
				c.AbortWithStatusJSON(500, "token atr was not present")
				return
			}
			// match the token atribute to the specified column from the policy
			queryDB = queryDB.Where(fmt.Sprintf("%s = ?", rls[0][3]), tokenAtr)
		}

		var count int64

		err = queryDB.Count(&count).Error
		if err != nil {
			c.AbortWithStatusJSON(500, err.Error())
			return
		}

		// get the page and page size
		page, _ := c.GetQuery("page")
		pageInt, err := strconv.Atoi(page)
		if err != nil {
			pageInt = 1
		} else {
			if pageInt < 1 {
				pageInt = 1
			}
		}

		pageSize, _ := c.GetQuery("pageSize")
		pageSizeInt, err := strconv.Atoi(pageSize)
		if err != nil {
			pageSizeInt = 10
		} else {
			switch {
			case pageSizeInt < 1:
				pageSizeInt = 1
			case pageSizeInt > 100:
				pageSizeInt = 100
			}
		}

		// calculate offset
		offset := (pageInt - 1) * pageSizeInt

		// Calculate total pages
		totalPages := count / int64(pageSizeInt)
		if count%int64(pageSizeInt) > 0 {
			totalPages++
		}

		// Set prevPage and nextPage to 0 if there is no previous or next page
		prevPage := pageInt - 1
		if prevPage <= 0 {
			prevPage = 1
		}

		nextPage := pageInt + 1
		if nextPage > int(totalPages) {
			nextPage = int(totalPages)
		}

		queryDB = queryDB.Offset(offset).Limit(pageSizeInt)

		rows, err := queryDB.Rows()
		if err != nil {
			c.AbortWithStatusJSON(404, "table "+table+" not found")
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
				c.AbortWithStatusJSON(500, "problem maping columns to struct")
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
			return
		}

		// return the result
		c.JSON(200, gin.H{
			"table":      table,
			"totalRows":  count,
			"totalPages": totalPages,
			"PrevPage":   prevPage,
			"NextPage":   nextPage,
			"data":       result,
		})
	})

	r.Run()
}
