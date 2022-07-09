package main

import (
	"github.com/zerjioang/bulkanalyzer"
	"github.com/zerjioang/bulkanalyzer/toolkit"
	"log"
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("CSV filepath is missing in CLI argument call")
	}
	// filepath contains the path to existing CSV file
	// however a malicious user can set any other file to be read
	// TODO add filepath validation
	filepath := os.Args[1]
	var analyzer bulkanalyzer.Analyzer
	err := analyzer.Run(filepath, &bulkanalyzer.Options{
		DockerImage:    "conkas:latest",
		ToolName:       "conkas",
		MaxContainers:  1,
		Remove0xPrefix: true,
		SkipHeaderRow:  true,
		Parser:         toolkit.ConkasParser,
		BuildCommand:   toolkit.ConkasCommand,
		OnFailedReturn: toolkit.ConkasFailedResult,
	})
	if err != nil {
		log.Fatal(err)
	}
}
