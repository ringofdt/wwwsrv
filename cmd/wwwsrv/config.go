package main

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

var (
	cfg = Config{}
)

// Config :
type Config struct {
	LogDebug       bool `envconfig:"LOG_DEBUG" default:"false"`
	HTTPSrvSetting HTTPSrvConfig
}

func loadConfig() {
	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Fatal(errors.Wrap(err, "Error parsing Config"))
	}

}
