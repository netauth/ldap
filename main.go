package main

import (
	"log"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/netauth/ldap/internal/ldap"
	"github.com/netauth/netauth/pkg/netauth"
	"github.com/spf13/viper"
)

func main() {
	var appLogger hclog.Logger

	llevel := os.Getenv("NETAUTH_LOGLEVEL")
	if llevel != "" {
		appLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "ldap-proxy",
			Level: hclog.LevelFromString(llevel),
		})
	} else {
		appLogger = hclog.NewNullLogger()
	}

	log.SetOutput(appLogger.Named("ldap.protocol").StandardWriter(&hclog.StandardLoggerOptions{ForceLevel: hclog.Trace}))
	log.SetPrefix("")
	log.SetFlags(0)

	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/netauth/")
	viper.AddConfigPath("$HOME/.netauth/")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		appLogger.Error("Error loading config", "error", err)
		os.Exit(5)
	}

	nacl, err := netauth.NewWithLog(appLogger.Named("netauth"))
	if err != nil {
		os.Exit(2)
	}

	ls := ldap.New(appLogger, nacl)

	ls.SetDomain("netauth.org")

	if err := ls.Serve("localhost:10389"); err != nil {
		appLogger.Error("Error serving", "error", err)
		return
	}
	appLogger.Info("Goodbye!")
}
