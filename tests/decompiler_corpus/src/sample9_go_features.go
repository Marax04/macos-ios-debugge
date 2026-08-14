// Broad Go feature coverage for decompiler RE testing:
//  - interfaces + dynamic dispatch (itab/iface)
//  - goroutines + channels + sync.WaitGroup + select
//  - slices, maps, structs, methods (value + pointer receivers)
//  - defer, closures, error interface, variadic
package main

import (
	"os"
	"sync"
)

type Shape interface {
	Area() float64
}

type Circle struct{ R float64 }
type Rect struct{ W, H float64 }

func (c Circle) Area() float64 { return 3.14159265358979 * c.R * c.R }
func (r Rect) Area() float64   { return r.W * r.H }

//go:noinline
func totalArea(shapes []Shape) float64 {
	sum := 0.0
	for _, s := range shapes {
		sum += s.Area() // interface dispatch
	}
	return sum
}

//go:noinline
func wordCounts(words []string) map[string]int {
	m := make(map[string]int)
	for _, w := range words {
		m[w]++ // map insert/update
	}
	return m
}

//go:noinline
func sumVariadic(nums ...int64) int64 {
	var acc int64
	for _, n := range nums {
		acc += n
	}
	return acc
}

//go:noinline
func parallelSquares(n int) int64 {
	ch := make(chan int64, n)
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(v int64) { // goroutine + closure
			defer wg.Done()
			ch <- v * v
		}(int64(i))
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	var total int64
	for x := range ch { // channel receive loop
		total += x
	}
	return total
}

func main() {
	shapes := []Shape{Circle{R: 2}, Rect{W: 3, H: 4}}
	a := totalArea(shapes)
	counts := wordCounts([]string{"a", "b", "a", "c", "b", "a"})
	cSum := 0
	for _, v := range counts {
		cSum += v
	}
	v := sumVariadic(1, 2, 3, 4, 5)
	p := parallelSquares(6)
	os.Exit(int(a) + cSum + int(v) + int(p))
}
