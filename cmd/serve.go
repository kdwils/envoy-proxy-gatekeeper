package cmd

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/kdwils/envoy-proxy-gatekeeper/config"
	"github.com/kdwils/envoy-proxy-gatekeeper/gatekeeper"
	"github.com/kdwils/envoy-proxy-gatekeeper/logger"
	"github.com/kdwils/envoy-proxy-gatekeeper/pkg/captcha"
	"github.com/kdwils/envoy-proxy-gatekeeper/pkg/jwt"
	"github.com/kdwils/envoy-proxy-gatekeeper/server"
	"github.com/kdwils/envoy-proxy-gatekeeper/template"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve the gatekeeper service",
	Long:  `serve the gatekeeper service`,
	Run: func(cmd *cobra.Command, args []string) {
		c, err := config.New(viper.GetViper())
		if err != nil {
			log.Fatal(err)
		}

		level := logger.LevelFromString(c.LogLevel)
		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		slogger := slog.New(handler)

		httpClient := http.Client{
			Timeout: c.Gatekeeper.Captcha.Timeout,
		}

		var provider jwt.Provider
		switch strings.ToLower(c.Gatekeeper.Captcha.Provider) {
		case "turnstile":
			provider, err = captcha.NewTurnstileProvider(c.Gatekeeper.Captcha.SecretKey, &httpClient)
		case "recaptcha":
			provider, err = captcha.NewRecaptchaProvider(c.Gatekeeper.Captcha.SecretKey, &httpClient)
		}
		if err != nil {
			log.Fatal(err)
		}

		templateStore, err := template.NewStore()
		if err != nil {
			log.Fatal(err)
		}

		trustedProxies := make([]*net.IPNet, 0)

		rateLimiter := server.NewRateLimiter(10, 20, server.WithTrustedProxies(trustedProxies), server.WithRealIp(gatekeeper.ExtractRealIP))

		tokenService := jwt.NewService(provider, c.Gatekeeper.Captcha.SigningKey, c.Gatekeeper.Captcha.SiteKey, c.Gatekeeper.Captcha.Timeout, c.Gatekeeper.Captcha.ChallengeDuration, c.Gatekeeper.Captcha.SessionDuration)

		gatekeeper := gatekeeper.New(&tokenService, trustedProxies)

		server := server.New(slogger, gatekeeper, templateStore, rateLimiter, c.Server.Scheme, c.Server.Host, c.Server.HTTPPort, c.Server.GRPCPort)

		log.Fatal(server.ServeDual(context.Background()))
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
