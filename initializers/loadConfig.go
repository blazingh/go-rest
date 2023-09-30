package initializers

import (
	"encoding/json"
	"os"
)

// Configuration structure
type Configuration struct {
	Roles []Role `json:"roles"`
}

// Role structure
type Role struct {
	Name   string  `json:"name"`
	Tables []Table `json:"tables"`
}

// Table structure
type Table struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

var RolesConfig Configuration

// LoadConfigFromFile loads the configuration from a JSON file
func LoadConfigFromFile(filename string) () {
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(fileContent, &RolesConfig)
	if err != nil {
		panic(err)
	}
}
