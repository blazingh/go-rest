package controllers

import (
	"fmt"
	"slices"
	"going/blazingh/test/initializers"
	"going/blazingh/test/utils"
	"regexp"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var operators = map[string]string{
	"eq": " = ?",            // equal
	"ne": "<> ?",            // not equal
	"lt": "< ?",             // less than
	"le": "<= ?",            // less than or equal
	"gt": "> ?",             // greater than
	"ge": ">= ?",            // greater than or equal
	"bw": "BETWEEN ? AND ?", // between
}

func extractKeyValue(input string) (string, string) {
	regex := regexp.MustCompile(`^([^[]+)(?:\[([^]]+)\])?$`)

	// Find submatches in the input string
	matches := regex.FindStringSubmatch(input)

	// If there is a match, return the key and the value (or "eq" if there is no value)
	if len(matches) == 3 {
		key := matches[1]
		value := matches[2]
		if value == "" {
			value = "eq"
		}
		return key, value
	}

	// If there is no match, return an empty string for both key and value
	return input, "eq"
}

func GetTable(c *gin.Context) {
	table := c.Param("table")

	if !utils.IsValidTableName(table) {
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
		// check each column for access
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
	queryDB := initializers.DB.Table(table).Select(availableColumns)

	// get the row level policy
	rls := initializers.Enforcer.GetFilteredNamedPolicy("p2", 0, role, table)

	// check for row level security in the policy
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

	allParams := c.Request.URL.Query()

	// remove reserved params from the query
	reservedParams := []string{"page", "page_size"}
	for _, param := range reservedParams {
		delete(allParams, param)
	}

	for key, value := range allParams {
		filterKey, filterOperator := extractKeyValue(key)
		//check if the filter key is in the available columns
		if !slices.Contains(availableColumns, filterKey) {
			c.AbortWithStatusJSON(400, "invalid filter parameter")
			return
		}
		operator, ok := operators[filterOperator]
		if !ok {
			c.AbortWithStatusJSON(400, "invalid operator")
			return
		}
		queryDB = queryDB.Where(fmt.Sprintf("%s %s", filterKey, operator), value[0])
	}

	// get the page and page size
	page, _ := c.GetQuery("page")
	pageSize, _ := c.GetQuery("pageSize")

	pageInt := utils.GetPageAsInt(page)
	pageSizeInt := utils.GetPageSizeAsInt(pageSize)

	// calculate offset and total pages
	offset := (pageInt - 1) * pageSizeInt
	totalPages := count / int64(pageSizeInt)
	if count%int64(pageSizeInt) > 0 {
		totalPages++
	}

	// Set prevPage and nextPage to 0 if there is no previous or next page
	prevPage := pageInt - 1
	nextPage := pageInt + 1

	if prevPage <= 0 {
		prevPage = 1
	}

	if nextPage > int(totalPages) {
		nextPage = int(totalPages)
	}

	// apply pagintaion
	queryDB = queryDB.Offset(offset).Limit(pageSizeInt)

	// excute the query
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
}
