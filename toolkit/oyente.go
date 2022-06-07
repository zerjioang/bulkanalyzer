package toolkit

import (
	"bytes"
	"fmt"
)

const (
	runCommand = `docker exec oyente bash -c "echo '%s' > /tmp/%s.bytecode && \
cd /oyente/oyente && \
python oyente.py -s /tmp/%s.bytecode -b && \
rm -rf /tmp/%s.bytecode"`
)

var (
	// OYENTE tool failed response
	failedResponse = [][]byte{[]byte("0"), []byte(""), []byte(""), []byte(""), []byte(""), []byte("0"), []byte("true")}
)

// runArbitraryCode("docker", args("run -it -d --name oyente luongnguyen/oyente")...)
// 1 copy code to file and run the analysis
// docker exec -it oyente bash -c "echo '0x6d4946c0e9f43f4dee607b0ef1fa1c3318585733ff' > /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode && \
// cd /oyente/oyente && \
// python oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b \
// rm -rf /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode"

// OyenteParser is the parser designed to convert OYENTE tool output to structured format
func OyenteParser(out []byte) [][]byte {
	none := []byte("")
	out = bytes.ReplaceAll(out, []byte("WARNING:root:You are using evm version 1.8.2. The supported version is 1.7.3"), none)
	out = bytes.ReplaceAll(out, []byte("WARNING:root:You are using solc version 0.4.21, The latest supported version is 0.4.19"), none)
	out = bytes.ReplaceAll(out, []byte("============ Results ==========="), none)
	out = bytes.ReplaceAll(out, []byte("====== Analysis Completed ======"), none)
	out = bytes.ReplaceAll(out, []byte(`INFO:symExec:`), none)
	out = bytes.ReplaceAll(out, []byte(`EVM Code Coverage:`), none)
	out = bytes.ReplaceAll(out, []byte(`Callstack Depth Attack Vulnerability:`), none)
	out = bytes.ReplaceAll(out, []byte(`Transaction-Ordering Dependence (TOD):`), none)
	out = bytes.ReplaceAll(out, []byte(`Timestamp Dependency:`), none)
	out = bytes.ReplaceAll(out, []byte(`Re-Entrancy Vulnerability:`), none)
	out = bytes.ReplaceAll(out, []byte(" "), none)
	out = bytes.ReplaceAll(out, []byte(` `), none)
	out = bytes.ReplaceAll(out, []byte("\n"), none)
	out = bytes.ReplaceAll(out, []byte("\r"), none)
	out = bytes.ReplaceAll(out, []byte("\t"), none)
	out = bytes.ReplaceAll(out, []byte("\b"), none)
	out = bytes.ReplaceAll(out, []byte("False"), []byte(`false,`))
	out = bytes.ReplaceAll(out, []byte("True"), []byte(`true,`))
	out = bytes.ReplaceAll(out, []byte(`%`), []byte(","))
	if out[len(out)-1] == ',' {
		out = out[0 : len(out)-1]
	}
	chunks := bytes.Split(out, []byte(","))
	return chunks
}

// OyenteCommand generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func OyenteCommand(address string, code string) string {
	// example command
	// docker exec -i oyente python /oyente/oyente/oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b
	return fmt.Sprintf(runCommand, code, address, address, address)
}
