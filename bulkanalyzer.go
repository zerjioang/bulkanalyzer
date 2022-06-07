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

	// make sure we have a valid parser set
	if opts.Parser == nil {
		return errors.New("a result parser is required before running the analysis")
	}
	// make sure we have a valid command builder set
	if opts.BuildCommand == nil {
		return errors.New("a command builder is required before running the analysis")
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
	if opts.Remove0xPrefix {
		if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
			// remove 0x prefix from bytecode. this is a requirement of OYENTE (for example)
			code = code[2:]
		}
	}
	scanContract := opts.BuildCommand(address, code)
	start := time.Now()
	result, err := runArbitraryCode("bash", []string{"-c", scanContract}...)
	if err != nil {
		return failedResponse
	}
	diff := time.Since(start).Milliseconds()
	output := opts.Parser([]byte(result))
	// append time value
	output = append(output, []byte(fmt.Sprintf("%d", diff)))
	// append no errored flag value
	output = append(output, []byte("false"))
	return output
}

func runArbitraryCode(command string, args ...string) (string, error) {
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
