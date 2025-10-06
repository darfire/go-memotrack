package main

import (
	"github.com/BurntSushi/toml"
)

type ObjectSpec struct {
	Type         uint8
	Name         string
	Allocators   []string `toml:"allocators"`
	Deallocators []string `toml:"deallocators"`
}

type Config struct {
	Objects    map[string]ObjectSpec `toml:"objects"`
	Executable string                `toml:"executable"`
}

func ParseConfig(path string) (Config, error) {
	var config Config

	_, err := toml.DecodeFile(path, &config)

	if err != nil {
		return Config{}, err
	}

	return config, nil
}
