package bulkanalyzer

// Options is a wrapper struct that contains all configurable parameters for specific analysis
type Options struct {
	// name of the docker image to execute
	DockerImage string
	// number of containers to deploy
	// this is required for parallel analysis execution using
	// different workers (containers)
	MaxContainers uint
	// flag to indicate if bytecode 0x prefix needs to be removed or not
	Remove0xPrefix bool
	// function used to parse the results of the analysis
	Parser func(out []byte) [][]byte
}
