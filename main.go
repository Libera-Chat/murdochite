package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/Libera-Chat/murdochite/bot"
	"github.com/op/go-logging"
	"github.com/pelletier/go-toml/v2"
)

// Version of the bot
var Version = "Unknown" // nolint:gochecknoglobals // set by the linker

func main() {
	//nolint:lll,misspell // cannot be shortened, and I'd love to spell correctly but the dev was apparently american.
	const format = "%{color}[%{time:15:04:05.0000}] [%{level: -8s}]%{color:reset} [%{module: -15s}] [%{shortfile: -20s}] %{message}"

	logging.SetFormatter(logging.MustStringFormatter(format))
	logging.SetBackend(logging.NewLogBackend(os.Stdout, "", 0))

	var config bot.Config

	data, err := os.ReadFile("./config.toml")
	if err != nil {
		fmt.Printf("Could not read config file: %s\n", err)
		os.Exit(1)
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		fmt.Printf("Could not parse config file: %s\n", err)
		os.Exit(1)
	}

	config.Version = Version
	mainLogger := logging.MustGetLogger("main")
	mainLogger.Infof("Starting version %s...", Version)

	b, err := bot.New(&config, logging.MustGetLogger("bot"))
	if err != nil {
		mainLogger.Fatalf("Could not instantiate bot: %s", err)
	}

	b.Run(context.Background())

	if b.ShouldRestart {
		exe, err := os.Executable()
		if err != nil {
			panic(err)
		}

		panic(syscall.Exec(exe, os.Args, os.Environ()))
	}
}
