package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/netauth/ldap/internal/ldap"
	"github.com/netauth/netauth/pkg/netauth"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("ldap.bind", "localhost:389")
	viper.SetDefault("ldap.tls", false)
	viper.SetDefault("ldap.key", "/var/lib/netauth/keys/ldap.key")
	viper.SetDefault("ldap.cert", "/var/lib/netauth/keys/ldap.cert")
	viper.SetDefault("ldap.allow_anon", false)
}

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
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
	})
	log.SetOutput(appLogger.Named("ldap.protocol").
		StandardWriter(
			&hclog.StandardLoggerOptions{
				ForceLevel: hclog.Trace,
			},
		),
	)

	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/netauth/")
	viper.AddConfigPath("$HOME/.netauth/")
	viper.AddConfigPath(".")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix("NETAUTH")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		appLogger.Error("Error loading config", "error", err)
		os.Exit(5)
	}

	nacl, err := netauth.NewWithLog(appLogger.Named("netauth"))
	if err != nil {
		appLogger.Error("Error initializing client", "error", err)
		os.Exit(2)
	}

	ls := ldap.New(
		ldap.WithLogger(appLogger),
		ldap.WithNetAuth(nacl),
		ldap.WithAnonBind(viper.GetBool("ldap.allow_anon")),
	)

	ls.SetDomain(viper.GetString("ldap.domain"))

	if !viper.GetBool("ldap.tls") {
		if !strings.HasPrefix(viper.GetString("ldap.bind"), "localhost") {
			appLogger.Warn("===================================================================")
			appLogger.Warn("  WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING  ")
			appLogger.Warn("===================================================================")
			appLogger.Warn("")
			appLogger.Warn("You are launching this server in plaintext mode!  This is allowable")
			appLogger.Warn("advisable when bound to localhost, and the bind configuration has")
			appLogger.Warn("been detected as not being bound to localhost.")
			appLogger.Warn("")
			appLogger.Warn("===================================================================")
			appLogger.Warn("  WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING  ")
			appLogger.Warn("===================================================================")
		}
		err = ls.Serve(viper.GetString("ldap.bind"))
	} else {
		err = ls.ServeTLS(
			viper.GetString("ldap.bind"),
			viper.GetString("ldap.key"),
			viper.GetString("ldap.cert"),
		)
	}
	if err != nil {
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
