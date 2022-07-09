package toolkit

// ConkasParser is the parser designed to convert CONKAS tool output to structured format
func ConkasParser(out []byte) ([][]byte, error) {
	return nil, nil
}

// ConkasCommand generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func ConkasCommand(containerName string, address string, code string) string {
	// example command
	return ""
}

// ConkasFailedResult returns Conkas default structured failed result data
func ConkasFailedResult() ([][]byte, error) {
	return nil, nil
}
