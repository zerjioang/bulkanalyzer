package toolkit

import (
	"bytes"
	"fmt"
)

const (
	runSecurifyCommand = `docker exec %s bash -c "echo '%s' > /tmp/%s.bytecode && \
java -jar build/libs/securify.jar --json -fh /tmp/%s.bytecode &&
rm -rf /tmp/%s.bytecode"`
)

var (
	sentences = []string{
		"Attempt to decompile the contract with methods...",
		" Success. Inlining methods...",
		"Failed to decompile methods. Attempt to decompile the contract without identifying methods...",
		"Propagating constants...",
		"Verifying patterns...",
	}
	none = []byte("")
)

// Securify1Parser is the parser designed to convert Securify1 tool output to structured format
func Securify1Parser(out []byte) ([][]byte, error) {
	// remove known sentences
	for _, item := range sentences {
		out = bytes.Replace(out, []byte(item), none, 1)
	}
	// trim spaces
	bytes.Trim(out, " ")
	return [][]byte{out}, nil
}

// Securify1Command generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func Securify1Command(containerName string, address string, code string) string {
	// example command
	// java -jar build/libs/securify.jar --json -fh /tmp/%s.bytecode

	// remove starting slash
	if containerName[0] == '/' {
		containerName = containerName[1:]
	}
	return fmt.Sprintf(runSecurifyCommand, containerName, code, address, address, address)
}

// Securify1FailedResult returns Securify1 default structured failed result data
func Securify1FailedResult() ([][]byte, error) {
	return failedResponse, nil
}
