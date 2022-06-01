package bulkanalyzer

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	basepath = "/home/sergio/GolandProjects/bulkanayzer/"
)

func TestBulkAnalyze(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", nil))
	})
	t.Run("sample-csv-100", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_100_samples.csv", nil))
	})
	t.Run("sample-csv-1000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_1000_samples.csv", nil))
	})
	t.Run("sample-csv-10000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_10000_samples.csv", nil))
	})
	t.Run("sample-csv-100000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_100000_samples.csv", nil))
	})
	t.Run("sample-csv-500000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_500000_samples.csv", nil))
	})
	t.Run("parse-oyente-output", func(t *testing.T) {
		exampleOutput := `WARNING:root:You are using evm version 1.8.2. The supported version is 1.7.3
WARNING:root:You are using solc version 0.4.21, The latest supported version is 0.4.19
INFO:symExec:	============ Results ===========
INFO:symExec:	  EVM Code Coverage: 			 100.0%
INFO:symExec:	  Callstack Depth Attack Vulnerability:  False
INFO:symExec:	  Transaction-Ordering Dependence (TOD): False
INFO:symExec:	  Timestamp Dependency: 		 False
INFO:symExec:	  Re-Entrancy Vulnerability: 		 False
INFO:symExec:	====== Analysis Completed ======
`
		chunks := parseOyenteOutput(exampleOutput)
		fmt.Println(chunks)
	})
}

func TestSplit(t *testing.T) {

}
