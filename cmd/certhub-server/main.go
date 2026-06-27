package main

import (
	"context"
	"os"

	"certhub/internal/commands"
)

func main() {
	runner := commands.ServerRunner{Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(runner.Execute(context.Background(), os.Args[1:]))
}
