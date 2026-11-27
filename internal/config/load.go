package config

import (
	"errors"
	"io"
	"os"

	"go.yaml.in/yaml/v4"
)

// Load reads one strict YAML document containing detection rules and action destinations.
func Load(path string) (cfg Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close() // nolint:errcheck

	var raw Config
	loader, err := yaml.NewLoader(file, yaml.WithKnownFields(), yaml.WithUniqueKeys())
	if err != nil {
		return Config{}, errors.New("invalid Warden YAML: cannot initialize loader")
	}

	if err := loader.Load(&raw); err != nil {
		return Config{}, errors.New("invalid Warden YAML: check field names, types and duplicates")
	}

	if err := loader.Load(new(any)); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("expected one YAML document")
	}

	return raw, nil
}
