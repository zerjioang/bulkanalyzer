package bulkanalyzer

import (
	"github.com/stretchr/testify/assert"
	"github.com/zerjioang/bulkanalyzer/toolkit"
	"testing"
)

const (
	// TODO remove this hardcoded variable and convert it to ENV
	basepath = "/home/sergio/go/src/github.com/zerjioang/bulkanalyzer/"
)

func TestBulkAnalyzeWithOyente(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  4,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
	t.Run("sample-csv-100", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_100_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
	t.Run("sample-csv-1000", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_1000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
	t.Run("sample-csv-10000", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_10000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
	t.Run("sample-csv-100000", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_100000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
	t.Run("sample-csv-500000", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_500000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			ToolName:       "oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.OyenteParser,
			BuildCommand:   toolkit.OyenteCommand,
			OnFailedReturn: toolkit.OyenteFailedResult,
		}))
	})
}

func TestBulkAnalyzeWithHoneybadger(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", &Options{
			DockerImage:    "christoftorres/honeybadger:latest",
			ToolName:       "honeybadger",
			MaxContainers:  4,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.HoneybadgerParser,
			BuildCommand:   toolkit.HoneybadgerCommand,
			OnFailedReturn: toolkit.HoneybadgerFailedResult,
		}))
	})
}

func TestBulkAnalyzeWithConkas(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", &Options{
			DockerImage:    "conkas:latest",
			ToolName:       "conkas",
			MaxContainers:  4,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.ConkasParser,
			BuildCommand:   toolkit.ConkasCommand,
			OnFailedReturn: toolkit.ConkasFailedResult,
		}))
	})
}

func TestBulkAnalyzeWithSecurify2(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		var analyzer Analyzer
		assert.NoError(t, analyzer.Run(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", &Options{
			DockerImage:    "troublor/securify2:latest",
			ToolName:       "securify2",
			MaxContainers:  4,
			Remove0xPrefix: true,
			SkipHeaderRow:  true,
			Parser:         toolkit.Securify2Parser,
			BuildCommand:   toolkit.Securify2Command,
			OnFailedReturn: toolkit.Securify2FailedResult,
		}))
	})
}

func TestParseResults(t *testing.T) {
	t.Run("parse-oyente-output", func(t *testing.T) {
		exampleOutput := `WARNING:root:You are using evm version 1.8.2. The supported version is 1.7.3
WARNING:root:You are using solc version 0.4.21, The latest supported version is 0.4.19
INFO:symExec:	============ Results ===========
INFO:symExec:	  EVM Code Coverage: 			         100.0%
INFO:symExec:	  Callstack Depth Attack Vulnerability:  False
INFO:symExec:	  Transaction-Ordering Dependence (TOD): False
INFO:symExec:	  Timestamp Dependency: 		         False
INFO:symExec:	  Re-Entrancy Vulnerability: 		     False
INFO:symExec:	====== Analysis Completed ======
`
		chunks, err := toolkit.OyenteParser([]byte(exampleOutput))
		str := chunksToString(chunks)
		assert.Equal(t, str, "100.0 false false false false")
		assert.NoError(t, err)
	})
}
