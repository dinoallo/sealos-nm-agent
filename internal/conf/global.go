package conf

import (
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var (
	k      = koanf.New(".")
	parser = yaml.Parser()
)

const (
	defaultAddr = "localhost"
	defaultPort = 30045
)

type GlobalUserConfig struct {
	Address                   string `koanf:"address"`
	Port                      uint32 `koanf:"port"`
	DebugUserConfig           `koanf:"debug"`
	RawTrafficStoreUserConfig `koanf:"raw_traffic_store"`
}

func NewGlobalUserConfig() GlobalUserConfig {
	return GlobalUserConfig{
		Address:                   defaultAddr,
		Port:                      defaultPort,
		DebugUserConfig:           NewDebugUserConfig(),
		RawTrafficStoreUserConfig: RawTrafficStoreUserConfig{},
	}
}

type DebugUserConfig struct {
	Enabled bool `koanf:"enabled"`
}

func NewDebugUserConfig() DebugUserConfig {
	return DebugUserConfig{
		Enabled: true,
	}
}

func ReadGlobalConfig(path string) (GlobalUserConfig, error) {
	globalConfig := NewGlobalUserConfig()
	if err := k.Load(file.Provider(path), parser); err != nil {
		return globalConfig, err
	}
	if err := k.Unmarshal("", &globalConfig); err != nil {
		return globalConfig, err
	}
	return globalConfig, nil
}

func PrintGlobalConfig() {
	k.Print()
}
