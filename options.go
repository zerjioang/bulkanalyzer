package bulkanalyzer

// Options is a wrapper struct that contains all configurable parameters for specific analysis
type Options struct {
	// name of the docker image to execute
	DockerImage string
	// name of the tool being used
	ToolName string
	// number of containers to deploy
	// this is required for parallel analysis execution using
	// different workers (containers)
	MaxContainers uint
	// flag to indicate if bytecode 0x prefix needs to be removed or not
	Remove0xPrefix bool
	// flag to indicate if we need to skip CSV header row
	SkipHeaderRow bool
	// function used to parse the results of the analysis
	Parser func(out []byte) ([][]byte, error)
	// function used to build the command that triggers the analysis
	BuildCommand func(containerName string, address string, code string) string
	// function that returns a pre-defined failed return result in a structured format
	OnFailedReturn func() ([][]byte, error)
	// debug flag to enable a more verbose output
	Debug bool
}

// ValidToolName returns true when tool name has a valid value
// Use this check to avoid directory traversing bugs
func (o Options) ValidToolName() bool {
	str := o.ToolName
	valid := true
	for i := 0; i < len(str) && valid; i++ {
		c := str[i]
		valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return valid
}
