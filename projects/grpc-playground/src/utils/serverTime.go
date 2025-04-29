package utils

import "time"

type Args struct{}

type TimeServer int64

func (t *TimeServer) GiveServerTime(args *Args, reply *int64) error {
	// fill reply pointer to send the data back
	*reply = time.Now().Unix()
	return nil
}
