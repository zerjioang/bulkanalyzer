package bulkanalyzer

import (
	"bufio"
	"bytes"
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

var (
	failedResponse = [][]byte{[]byte("0"), []byte(""), []byte(""), []byte(""), []byte(""), []byte("0"), []byte("true")}
)

func ExistFile(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		return false
	}
	return true
}

func BulkAnalyze(csvPath string, opts *Options) error {
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

	if opts.MaxContainers == 0 {
		// at least 1 containers is required always
		opts.MaxContainers = 1
	}

	// now make sure required containers exists and are running
	// if none found, we run the required ones
	for i := uint(0); i < opts.MaxContainers; i++ {
		runTargetContainer(i, opts.DockerImage)
	}

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
		// sequential analysis
		// TODO add support for concurrent jobs
		if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
			log.Printf("Analyzing contract %s with code size %d:\n", address, len(code))
			result := triggerScanJob(address, code, opts)
			fmt.Println(result)
		}
	}
	if err != io.EOF {
		return err
	}
	return nil
}

// runTargetContainer will run the requested docker image into a new container
func runTargetContainer(containerIdx uint, dockerImageName string) {

}

func triggerScanJob(address string, code string, opts *Options) [][]byte {
	// first thing: input data validation to avoid RCE
	if err := IsValidAddress(address); err != nil {
		panic(err)
	}
	if err := IsValidBytecode(code); err != nil {
		panic(err)
	}
	// run docker image in background
	// runArbitraryCode("docker", args("run -it -d --name oyente luongnguyen/oyente")...)
	// 1 copy code to file and run the analysis
	// docker exec -it oyente bash -c "echo '0x6d4946c0e9f43f4dee607b0ef1fa1c3318585733ff' > /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode && \
	// cd /oyente/oyente && \
	// python oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b \
	// rm -rf /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode"
	if opts.Remove0xPrefix {
		if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
			// remove 0x prefix from bytecode. this is a requirement of OYENTE (for example)
			code = code[2:]
		}
	}
	scanContract := fmt.Sprintf(runCommand, code, address, address, address)
	// 2 run analysis
	// example command
	// docker exec -i oyente python /oyente/oyente/oyente.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b
	// 3 get the results
	start := time.Now()
	result, err := runScanCode("bash", []string{"-c", scanContract}...)
	if err != nil {
		return failedResponse
	}
	diff := time.Since(start).Milliseconds()
	output := OyenteParser([]byte(result))
	// append time value
	output = append(output, []byte(fmt.Sprintf("%d", diff)))
	// append no errored flag value
	output = append(output, []byte("false"))
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
