package initializers

import (
	"github.com/casbin/casbin/v2"
)

var Enforcer *casbin.Enforcer

func LoadCasbinConfig(modelFile string, configFile string) {
	var err error
	Enforcer, err = casbin.NewEnforcer(modelFile, configFile)

	if err != nil {
		panic(err)
	}
}

