package bulkanalyzer

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
)

func ExistFile(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		return false
	}
	return true
}
func BulkAnalyze(csvPath string, options *Options) error {
	if !ExistFile(csvPath) {
		return errors.New("provided CSV file does not exists")
	}
	// open file
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}

	// remember to close the file at the end of the program
	defer f.Close()

	// read csv values using csv.Reader
	csvReader := csv.NewReader(f)
	var readErr error
	var row []string
	for err == nil {
		row, readErr = csvReader.Read()
		if readErr != nil {
			return readErr
		}
		// handle row
		fmt.Println(row)
	}
	return nil
}
