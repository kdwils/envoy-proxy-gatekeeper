package config

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	LogLevel       string     `yaml:"logLevel" json:"logLevel"`
	Server         Server     `yaml:"server" json:"server"`
	TrustedProxies []string   `yaml:"trustedProxies" json:"trustedProxies"`
	Gatekeeper     Gatekeeper `yaml:"gatekeeper" json:"gatekeeper"`
}

type Server struct {
	GRPCPort int    `yaml:"grpcPort" json:"grpcPort"`
	HTTPPort int    `yaml:"httpPort" json:"httpPort"`
	Host     string `yaml:"host" json:"host"`
	Scheme   string `yaml:"scheme" json:"scheme"`
}

type Gatekeeper struct {
	Captcha Captcha `yaml:"captcha" json:"captcha"`
}

type Captcha struct {
	Provider          string        `yaml:"provider" json:"provider"`
	SiteKey           string        `yaml:"siteKey" json:"siteKey"`
	SecretKey         string        `yaml:"secretKey" json:"secretKey"`
	SigningKey        string        `yaml:"signingKey" json:"signingKey"`
	CookieDomain      string        `yaml:"cookieDomain" json:"cookieDomain"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	ChallengeDuration time.Duration `yaml:"challengeDuration" json:"challengeDuration"`
	SessionDuration   time.Duration `yaml:"sessionDuration" json:"sessionDuration"`
}

func New(v *viper.Viper) (Config, error) {
	c := Config{}
	if v == nil {
		return c, errors.New("viper not initialized")
	}
	if v.ConfigFileUsed() != "" {
		err := v.ReadInConfig()
		if err != nil {
			return c, err
		}
	}
	err := v.Unmarshal(&c)
	return c, err
}
