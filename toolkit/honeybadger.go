package toolkit

// Implementation of Honeybadger required methods
// tool: https://github.com/christoftorres/HoneyBadger

// HoneybadgerParser is the parser designed to convert Honeybadger tool output to structured format
func HoneybadgerParser(out []byte) ([][]byte, error) {
	return nil, nil
}

// HoneybadgerCommand generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func HoneybadgerCommand(address string, code string) string {
	// example command
	return ""
}

// HoneybadgerFailedResult returns Honeybadger default structured failed result data
func HoneybadgerFailedResult() ([][]byte, error) {
	return nil, nil
}
