package bulkanalyzer

import (
	"strings"
)

// chunksToString is a debugging method used to convert a slice of bytes to string
func chunksToString(chunks [][]byte) string {
	sb := strings.Builder{}
	for i := 0; i < len(chunks)-1; i++ {
		sb.WriteString(string(chunks[i]))
		sb.WriteString(" ")
	}
	sb.WriteString(string(chunks[len(chunks)-1]))
	return sb.String()
}
