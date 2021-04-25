package main

import (
	"fmt"
)

func ReadN(i, n int) {
	if n == 0 {
		return
	}

	// Each of the test cases will consist of a line with an integer X (0 < X <= 100),
	// followed by another line consisting of X number of space-separated integers Yn (-100 <= Yn <= 100).
	var x int
	_, err := fmt.Scanf("%d", &x)
	if err != nil {
		panic(err)
		return
	}

	// Read x number of integers
	numbers := make([]int, x)
	sum := 0
	ReadX(numbers, 0, x, &sum)
	fmt.Println(sum)

	ReadN(i+1, n-1)
}

func ReadX(all []int, i, x int, sum *int) {
	if x == 0 {
		return
	}
	if m, err := Scan(&all[i]); m != 1 {
		panic(err)
	}

	v := all[i]
	*sum += v * v
	ReadX(all, i+1, x-1, sum)
}

func Scan(a *int) (int, error) {
	return fmt.Scan(a)
}

func main() {
	// The first line of the input will be an integer N (1 <= N <= 100), indicating the number of test cases to follow.
	var n int
	_, err := fmt.Scanf("%d", &n)
	if err != nil {
		panic(err)
		return
	}

	// Read and process X based on number of N
	ReadN(0, n)
}
