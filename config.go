package main

import (
	"github.com/BurntSushi/toml"
)

type ObjectSpec struct {
	Type         uint16
	Name         string
	Allocators   []string `toml:"allocators"`
	Deallocators []string `toml:"deallocators"`
}

type Config struct {
	Objects         map[string]ObjectSpec `toml:"objects"`
	Executable      string                `toml:"executable"`
	SampleSeconds   int                   `toml:"sample_seconds"`
	MaxStatsBuckets int                   `toml:"max_stats_buckets"`
	References      []string              `toml:"references"`
}

func ParseConfig(path string) (Config, error) {
	config := Config{
		Objects:         make(map[string]ObjectSpec),
		Executable:      "",
		SampleSeconds:   10,
		MaxStatsBuckets: 1024,
	}

	_, err := toml.DecodeFile(path, &config)

	if err != nil {
		return Config{}, err
	}

	return config, nil
}
