package bulkanalyzer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/zerjioang/bulkanalyzer/docker"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Analyzer struct {
	// analyzer configuration parameters
	opts *Options
	// docker container manager
	dockerManager docker.ContainerManager
}

func (bulk *Analyzer) ExistFile(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		return false
	}
	return true
}

func (bulk *Analyzer) Run(csvPath string, opts *Options) error {
	bulk.opts = opts
	if !bulk.ExistFile(csvPath) {
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
		bulk.runTargetContainer(i)
	}

	// read csv values using csv.Reader
	csvReader := csv.NewReader(f)

	// open file
	fout, err := os.Create(csvPath + "_out.csv")
	if err != nil {
		return err
	}
	csvWriter := csv.NewWriter(fout)
	defer func() {
		csvWriter.Flush()
		_ = fout.Close()
	}()

	var readErr error
	var row []string
	// sequential analysis
	// TODO add support for concurrent jobs using a worker pool and N docker containers
	if bulk.opts.SkipHeaderRow {
		_, _ = csvReader.Read()
	}
	for readErr == nil {
		row, readErr = csvReader.Read()
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			continue
		}
		address := row[1]
		code := row[2]
		log.Printf("Analyzing contract %s with code size %d:\n", address, len(code))
		if opts.Remove0xPrefix {
			if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
				code = code[2:]
			}
		}
		result := bulk.triggerScanJob(address, code)
		// append sample identifier to the result
		result = append(result, []byte(address))
		if writeErr := csvWriter.Write(chunksToCSVrow(result)); writeErr != nil {
			log.Println("error while csv writing:", writeErr)
		}
		log.Println(chunksToString(result))
	}
	return nil
}

// runTargetContainer will run the requested docker image into a new container
func (bulk *Analyzer) runTargetContainer(containerIdx uint) {
	opts := bulk.opts
	imageName := opts.DockerImage
	log.Println("Checking container", imageName)
}

func (bulk *Analyzer) triggerScanJob(address string, code string) [][]byte {
	// first thing: input data validation to avoid RCE
	if err := IsValidAddress(address); err != nil {
		panic(err)
	}
	if err := IsValidBytecode(code); err != nil {
		panic(err)
	}
	// run docker image in background
	opts := bulk.opts
	if opts.Remove0xPrefix {
		if len(code) > 2 && code[0] == '0' && code[1] == 'x' {
			// remove 0x prefix from bytecode. this is a requirement of OYENTE (for example)
			code = code[2:]
		}
	}
	scanContract := opts.BuildCommand(address, code)
	start := time.Now()
	result, err := bulk.runArbitraryCode("bash", []string{"-c", scanContract}...)
	if err != nil {
		return opts.OnFailedReturn()
	}
	diff := time.Since(start).Milliseconds()
	output := opts.Parser([]byte(result))
	// append time value
	output = append(output, []byte(fmt.Sprintf("%d", diff)))
	// append no errored flag value
	output = append(output, []byte("false"))
	return output
}

// runArbitraryCode runs given command with arguments
// WARNING: be very careful when calling this function!
func (bulk *Analyzer) runArbitraryCode(command string, args ...string) (string, error) {
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
