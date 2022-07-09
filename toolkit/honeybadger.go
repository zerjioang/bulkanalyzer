package toolkit

import (
	"fmt"
	"strings"
)

// Implementation of Honeybadger required methods
// tool: https://github.com/christoftorres/HoneyBadger

const (
	runHoneyBadgerCommand = `docker exec %s bash -c "echo '%s' > /tmp/%s.bytecode && \
cd /root/honeybadger && \
python honeybadger.py -s /tmp/%s.bytecode -b && \
rm -rf /tmp/%s.bytecode"`
)

// HoneybadgerParser is the parser designed to convert Honeybadger tool output to structured format
func HoneybadgerParser(out []byte) ([][]byte, error) {
	// Example output
	/*

		                       ___,,___
		                 _,-='=- =-  -`''--.__,,.._
		              ,-;// /  - -       -   -= - '=.
		            ,'///    -     -   -   =  - ==-=\`.
		           |/// /  =    `. - =   == - =.=_,,._ `=/|
		          ///    -   -    \  - - = ,ndDMHHMM  \
		        ,' - / /        / /\ =  - /MM(,,._`YQMML  `|
		       <_,=^Kkm / / / / ///H|wnWWdMKKK#''-;. `'0\  |
		              `''QkmmmmmnWMMM''WHMKKMM\   `--.  \> \
		                    `'''  `->>>    ``WHMb,.    `-_<@)
		                                      `'QMM`.
		                                         `>>>
		  _    _                        ____            _
		 | |  | |                      |  _ \          | |
		 | |__| | ___  _ __   ___ _   _| |_) | __ _  __| | __ _  ___ _ __
		 |  __  |/ _ \| '_ \ / _ \ | | |  _ < / _` |/ _` |/ _` |/ _ \ '__|
		 | |  | | (_) | | | |  __/ |_| | |_) | (_| | (_| | (_| |  __/ |
		 |_|  |_|\___/|_| |_|\___|\__, |____/ \__,_|\__,_|\__, |\___|_|
		                           __/ |                   __/ |
		                          |___/                   |___/


		INFO:root:Contract honeypots/MultiplicatorX3.sol:MultiplicatorX3:
		INFO:symExec:Running, please wait...
		INFO:symExec:	============ Results ===========
		INFO:symExec:	 EVM code coverage: 	 99.8%
		INFO:symExec:	 Money flow:    	 True
		INFO:symExec:	 Balance disorder: 	 True
		honeypots/MultiplicatorX3.sol:MultiplicatorX3:33:13
		adr.transfer(this.balance+msg.value)
		^
		INFO:symExec:	 Hidden transfer: 	 False
		INFO:symExec:	 Inheritance disorder: 	 False
		INFO:symExec:	 Uninitialised struct: 	 False
		INFO:symExec:	 Type overflow: 	 False
		INFO:symExec:	 Skip empty string: 	 False
		INFO:symExec:	 Hidden state update: 	 False
		INFO:symExec:	 Straw man contract: 	 False
		INFO:symExec:	 --- 33.6033570766 seconds ---
		INFO:symExec:	====== Analysis Completed ======
	*/
	raw := string(out)
	lines := strings.Split(raw, "INFO:symExec:\t ")
	var names []string
	var structured [][]byte
	for _, l := range lines {
		if strings.Contains(l, "Running, please wait...") {
			continue
		}
		if strings.Contains(l, "====== Analysis Completed ======") {
			// extract timing information
			continue
		}
		k, v := structureRow(l)
		if k != "" && v != "" {
			names = append(names, k)
			structured = append(structured, []byte(v))
		}
	}
	//fmt.Println(names)
	//fmt.Println(structured)
	return structured, nil
}

func structureRow(row string) (string, string) {
	row = strings.Replace(row, "INFO:symExec:", "", 1)
	row = strings.Replace(row, "\t", "", -1)
	row = strings.Replace(row, "\n", "", -1)
	row = strings.Replace(row, "\b", "", -1)
	row = strings.Replace(row, "\r", "", -1)
	row = strings.ToLower(row)
	chunks := strings.Split(row, ": ")
	if len(chunks) == 2 {
		key := chunks[0]
		key = strings.Replace(key, " ", "_", -1)
		value := chunks[1]
		// remove empty spaces
		value = strings.Trim(value, " ")
		// remove % symbol
		value = strings.Replace(value, "%", "", -1)
		return key, value
	}
	return "", ""
}

// HoneybadgerCommand generates the CLI command that triggers the analysis
// NOTE: make sure that input data is correctly sanitized
func HoneybadgerCommand(containerName string, address string, code string) string {
	// example command
	// docker exec -i oyente python /root/honeybadger/honeybadger.py -s /tmp/0x5519ab3fa3fa3a5adce56bc57905195d1599f6b2.bytecode -b

	// remove starting slash
	if containerName[0] == '/' {
		containerName = containerName[1:]
	}
	return fmt.Sprintf(runHoneyBadgerCommand, containerName, code, address, address, address)
}

// HoneybadgerFailedResult returns Honeybadger default structured failed result data
func HoneybadgerFailedResult() ([][]byte, error) {
	return nil, nil
}
