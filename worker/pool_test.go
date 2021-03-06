package worker

import (
	"fmt"
	"github.com/gammazero/workerpool"
	"testing"
)

func TestPool(t *testing.T) {
	wp := workerpool.New(4)
	requests := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for _, r := range requests {
		r := r
		wp.Submit(func() {
			fmt.Println("Handling request:", r)
		})
	}
	wp.StopWait()
}
