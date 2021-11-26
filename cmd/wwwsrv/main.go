package main

import (
	// goflag "flag"

	"flag"
	"os"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

const (
	TimeLayoutDate     = "2006-01-02"
	TimeLayoutDateTime = "2006-01-02 15:04:05"
)

var (
	// GitCommit : git commit hash
	GitCommit = "---"
	log       *logrus.Logger
)

func init() {

	logFormatter := &prefixed.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05.000000",
		FullTimestamp:   true,
		ForceFormatting: true,
	}
	logrus.SetFormatter(logFormatter)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)
	log = logrus.StandardLogger()
	envFile := ""
	flag.StringVar(&envFile, "env", "", "env file")

	loadEnv(envFile)
	loadConfig()
	if cfg.LogDebug {
		logrus.SetLevel(logrus.DebugLevel)
		log.SetLevel(logrus.DebugLevel)
		log.Debugf("%+v", cfg)
	}
}

func loadEnv(envFile string) {
	var err error
	if len(envFile) > 0 {
		err = godotenv.Load(envFile)
		if err != nil {
			log.Fatalf("ErrLoading env file: %v", envFile)
		}
		log.Infof("Loaded: %v", envFile)
		return
	}
	err = godotenv.Load(".env.local")
	if err == nil {
		log.Warn("Loaded: .env.local")
		return
	}
	err = godotenv.Load(".env")
	if err != nil {
		log.Warn("No .env Loaded")
	} else {
		log.Info("Loaded: .env")
	}
}

func main() {
	var err error
	_ = err

	log.Infof("App Start ver:%v", GitCommit)

	NewHTTPSrv(cfg.HTTPSrvSetting).Serve()

}
