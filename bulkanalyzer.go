package bulkanalyzer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	runCommand = `docker exec oyente bash -c "echo '%s' > /tmp/%s.bytecode && \
cd /oyente/oyente && \
python oyente.py -s /tmp/%s.bytecode -b && \
rm -rf /tmp/%s.bytecode"`
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
		address := row[1]
		code := row[2]
		if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
			log.Printf("Analyzing contract %s with code size %d:\n", address, len(code))
			result := triggerScanJob(address, code)
			fmt.Println(result)
		}
	}
	if err != io.EOF {
		return err
	}
	return nil
}

func triggerScanJob(address string, code string) []string {
	// run docker image in background
	// runArbitraryCode("docker", args("run -it -d --name oyente luongnguyen/oyente")...)
	// 1 copy code to file and run the analysis
	// docker exec -it oyente bash -c "echo '0x6d4946c0e9f43f4dee607b0ef1fa1c3318585733ff' > /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode && \
	// cd /oyente/oyente && \
	// python oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b \
	// rm -rf /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode"
	scanContract := fmt.Sprintf(runCommand, strings.ReplaceAll(code, "0x", ""), address, address, address)
	// 2 run analysis
	// example command
	// docker exec -i oyente python /oyente/oyente/oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b
	// 3 get the results
	start := time.Now()
	result, err := runScanCode("bash", []string{"-c", scanContract}...)
	if err != nil {

	}
	diff := time.Since(start).Milliseconds()
	output := parseOyenteOutput(result)
	output = append(output, fmt.Sprintf("%d", diff))
	fmt.Println(output)
	return output
}

func runArbitraryCode(command string, args ...string) {
	cmd := exec.Command(command, args...)
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	scanner := bufio.NewScanner(stderr)
	var b strings.Builder
	for scanner.Scan() {
		b.WriteString(scanner.Text())
	}
	if err != nil {
		log.Println(err.Error())
	}
}

func runScanCode(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	scanner := bufio.NewScanner(stderr)
	var b strings.Builder
	for scanner.Scan() {
		b.WriteString(scanner.Text())
	}
	return b.String(), err
}

func parseOyenteOutput(out string) []string {
	out = strings.ReplaceAll(out, "WARNING:root:You are using evm version 1.8.2. The supported version is 1.7.3", "")
	out = strings.ReplaceAll(out, "WARNING:root:You are using solc version 0.4.21, The latest supported version is 0.4.19", "")
	out = strings.ReplaceAll(out, "============ Results ===========", "")
	out = strings.ReplaceAll(out, "INFO:symExec:\t====== Analysis Completed ======", "")
	out = strings.ReplaceAll(out, `INFO:symExec:	`, "")
	out = strings.ReplaceAll(out, `EVM Code Coverage:`, "")
	out = strings.ReplaceAll(out, `Callstack Depth Attack Vulnerability:`, "")
	out = strings.ReplaceAll(out, `Transaction-Ordering Dependence (TOD):`, "")
	out = strings.ReplaceAll(out, `Timestamp Dependency:`, "")
	out = strings.ReplaceAll(out, `Re-Entrancy Vulnerability:`, "")
	out = strings.ReplaceAll(out, " ", "")
	out = strings.ReplaceAll(out, ` `, "")
	out = strings.ReplaceAll(out, "\n", "")
	out = strings.ReplaceAll(out, "\r", "")
	out = strings.ReplaceAll(out, "\t", "")
	out = strings.ReplaceAll(out, "\b", "")
	out = strings.ReplaceAll(out, "False", `false,`)
	out = strings.ReplaceAll(out, "True", `true,`)
	out = strings.ReplaceAll(out, `%`, ",")
	if out[len(out)-1] == ',' {
		out = out[0 : len(out)-1]
	}
	chunks := strings.Split(out, ",")
	return chunks
}
