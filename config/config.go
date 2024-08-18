package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	ServerConfig ServerConfig `mapstructure:"server"`
	RedisConfig  RedisConfig  `mapstructure:"redis"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

func GetConfig() *Config {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigName("config.yaml")
	v.AddConfigPath("./config")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	var cfg Config
	err = v.Unmarshal(&cfg)
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	return &cfg
}
