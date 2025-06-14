package main

import (
	"fmt"
	"sync"
)

var mutex sync.Mutex

func buyTicket(wg *sync.WaitGroup, userId int, remainingTickets *int) {
	defer wg.Done()

	mutex.Lock()

	if *remainingTickets > 0 {
		*remainingTickets--
		fmt.Printf("User %d purchased a ticket. Ticket remaining: %d\n", userId, *remainingTickets)
	} else {
		fmt.Printf("User %d found no ticket.\n", userId)
	}

	mutex.Unlock()
}

func main() {
	tickets := 500

	var wg sync.WaitGroup

	for userId := 0; userId < 2000; userId++ {
		wg.Add(1)

		go buyTicket(&wg, userId, &tickets)
	}

	wg.Wait()
}
