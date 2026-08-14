// Exercises: struct field recovery, loop-flag conditions, slice indexing.
// Go binaries are statically linked with a distinct runtime/ABI; this sample
// tests how the decompiler recovers user code amid the Go runtime.
package main

import "os"

type Point struct {
	X   int64
	Y   int64
	Sum int64
}

//go:noinline
func accumulate(pts []Point) int64 {
	var total int64 = 0
	for i := 0; i < len(pts); i++ {
		pts[i].Sum = pts[i].X + pts[i].Y
		total += pts[i].Sum
	}
	return total
}

//go:noinline
func findMax(arr []int64) int64 {
	best := arr[0]
	for i := 1; i < len(arr); i++ {
		if arr[i] > best {
			best = arr[i]
		}
	}
	return best
}

func main() {
	pts := []Point{{1, 2, 0}, {3, 4, 0}, {5, 6, 0}}
	t := accumulate(pts)
	arr := []int64{10, 40, 20, 30}
	m := findMax(arr)
	os.Exit(int(t + m))
}
