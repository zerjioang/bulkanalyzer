package main

import (
	"github.com/zerjioang/bulkanayzer"
	"github.com/zerjioang/bulkanayzer/toolkit"
	"log"
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("CSV filepath is missing in CLI argument call")
	}
	// filepath contains the path to existing CSV file
	// however a malicious user can set any other file to be readed
	// TODO add filepath validation
	filepath := os.Args[1]
	err := bulkanalyzer.BulkAnalyze(filepath, &bulkanalyzer.Options{
		DockerImage:    "luongnguyen/oyente",
		MaxContainers:  1,
		Remove0xPrefix: true,
		Parser:         toolkit.OyenteParser,
		BuildCommand:   toolkit.OyenteCommand,
	})
	if err != nil {
		log.Fatal(err)
	}
}
