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
		DockerImage:    "troublor/securify2",
		ToolName:       "securify2",
		MaxContainers:  1,
		Remove0xPrefix: true,
		SkipHeaderRow:  true,
		Parser:         toolkit.Securify2Parser,
		BuildCommand:   toolkit.Securify2Command,
		OnFailedReturn: toolkit.Securify2FailedResult,
	})
	if err != nil {
		log.Fatal(err)
	}
}
