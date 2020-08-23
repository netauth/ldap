package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// Take over the built in logger and set it up for Trace level
	// priority.  The only thing that logs at this priority are
	// protocol messages from the underlying ldap server mux.
	log.SetOutput(appLogger.Named("ldap.protocol").
		StandardWriter(
			&hclog.StandardLoggerOptions{
				ForceLevel: hclog.Trace,
			},
		),
	)
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

	ls.SetDomain(viper.GetString("ldap.domain"))

	if err := ls.Serve(viper.GetString("ldap.bind")); err != nil {
		appLogger.Error("Error serving", "error", err)
		return
	}

	// Sit here and wait for a signal to shutdown.
	ch := make(chan os.Signal, 5)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ls.Stop()

	appLogger.Info("Goodbye!")
}
