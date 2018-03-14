package main

import (
	"log"

	"github.com/enj/kms/pkg/cmd/kms"
)

func main() {
	if err := kms.Execute(); err != nil {
		log.Fatal(err)
	}
}
