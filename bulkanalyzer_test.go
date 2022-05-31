package bulkanalyzer

import (
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
}
