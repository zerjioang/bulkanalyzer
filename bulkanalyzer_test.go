package bulkanalyzer

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

const (
	// TODO remove this hardcoded variable and convert it to ENV
	basepath = "/home/sergio/GolandProjects/bulkanayzer/"
)

func TestBulkAnalyze(t *testing.T) {
	t.Run("sample-csv-10", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_10_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
		}))
	})
	t.Run("sample-csv-100", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_100_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
		}))
	})
	t.Run("sample-csv-1000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_1000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
		}))
	})
	t.Run("sample-csv-10000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_10000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
		}))
	})
	t.Run("sample-csv-100000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_100000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
		}))
	})
	t.Run("sample-csv-500000", func(t *testing.T) {
		assert.NoError(t, BulkAnalyze(basepath+"testdata/eth_contracts_2020_2022_500000_samples.csv", &Options{
			DockerImage:    "luongnguyen/oyente",
			MaxContainers:  1,
			Remove0xPrefix: true,
			Parser:         OyenteParser,
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
		chunks := OyenteParser([]byte(exampleOutput))
		sb := strings.Builder{}
		for i := 0; i < len(chunks)-1; i++ {
			sb.WriteString(string(chunks[i]))
			sb.WriteString(" ")
		}
		sb.WriteString(string(chunks[len(chunks)-1]))
		assert.Equal(t, sb.String(), "100.0 false false false false")
	})
}
