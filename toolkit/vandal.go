package toolkit

// VandalParser is the parser designed to convert VANDAL tool output to structured format
func VandalParser(out []byte) ([][]byte, error) {
	return nil, nil
}

// VandalCommand generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func VandalCommand(containerName string, address string, code string) string {
	// example command
	return ""
}

// VandalFailedResult returns Vandal default structured failed result data
func VandalFailedResult() ([][]byte, error) {
	return nil, nil
}
