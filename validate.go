package bulkanalyzer

import (
	"errors"
	"regexp"
)

var (
	// address validation regex
	addressRe = regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	// bytecode validation regex
	bytecodeRe = regexp.MustCompile("^(0x)?[0-9a-fA-F]+$")
)

// IsValidAddress return error when invalid address is provided
func IsValidAddress(addr string) error {
	if addr == "" {
		return errors.New("empty address provided")
	}
	if !addressRe.MatchString(addr) {
		return errors.New("invalid address")
	}
	return nil
}

// IsValidBytecode return error when invalid bytecode sequence is provided
func IsValidBytecode(bytecode string) error {
	if bytecode == "" {
		return errors.New("empty bytecode provided")
	}
	if !bytecodeRe.MatchString(bytecode) {
		return errors.New("invalid bytecode")
	}
	return nil
}
