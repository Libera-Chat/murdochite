package main

import (
	"context"
	"fmt"
	"os"

	"awesome-dragon.science/go/murdochite/bot"
	"github.com/op/go-logging"
	"github.com/pelletier/go-toml/v2"
)

func init() {
	//nolint:lll,misspell // cannot be shortened, and I'd love to spell correctly but the dev was apparently american.
	const format = "%{color}[%{time:15:04:05.0000}] [%{level: -8s}]%{color:reset} [%{module: -15s}] [%{shortfile: -15s}] %{message}"

	logging.SetFormatter(logging.MustStringFormatter(format))
	logging.SetBackend(logging.NewLogBackend(os.Stdout, "", 0))
}

func main() {
	var config bot.Config

	data, err := os.ReadFile("./config.toml")
	if err != nil {
		fmt.Printf("Could not read config file: %s", err)
		os.Exit(1)
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		fmt.Printf("Could not parse config file: %s", err)
		os.Exit(1)
	}

	b := bot.New(&config, logging.MustGetLogger("bot"))

	b.Run(context.Background())
}
