package main

import (
	"log"

	"github.com/enj/citadel/pkg/cmd/citadel"
)

func main() {
	if err := citadel.Execute(); err != nil {
		log.Fatal(err)
	}
}
