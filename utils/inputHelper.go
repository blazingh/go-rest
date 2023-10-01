package utils

import (
	"regexp"
	"strconv"
)

func IsValidTableName(name string) bool {
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

func GetPageAsInt(page string) int {
	pageInt, err := strconv.Atoi(page)
	if err != nil {
		pageInt = 1
	} else {
		if pageInt < 1 {
			pageInt = 1
		}
	}

	return pageInt
}

func GetPageSizeAsInt(pageSize string) int {
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

	return pageSizeInt
}
