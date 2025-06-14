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

func buyTicketChan(wg *sync.WaitGroup, ticketChan chan int, userId int) {
	defer wg.Done()

	ticketChan <- userId
}

func regularWay() {
	tickets := 500

	var wg sync.WaitGroup

	for userId := 0; userId < 2000; userId++ {
		wg.Add(1)

		go buyTicket(&wg, userId, &tickets)
	}

	wg.Wait()
}

func chanWay() {
	var wg sync.WaitGroup
	tickets := 500
	ticketChan := make(chan int)
	doneChan := make(chan bool)

	go manageTicket(ticketChan, doneChan, &tickets)

	for userId := 0; userId < 2000; userId++ {
		wg.Add(1)

		go buyTicketChan(&wg, ticketChan, userId)
	}

	wg.Wait()
	doneChan <- true
}

func manageTicket(ticketChan chan int, doneChan chan bool, tickets *int) {
	for {
		select {
		case user := <-ticketChan:
			if *tickets > 0 {
				*tickets--
				fmt.Printf("User %d purchased a ticket. Ticket remaining: %d\n", user, *tickets)
			} else {
				fmt.Printf("User %d found no ticket.\n", user)
			}
		case <-doneChan:
			fmt.Printf("Ticket remaining: %d\n", *tickets)
		}
	}
}

func main() {

	// regularWay()

	chanWay()
}
