package main

import (
	"bufio"
	"flag"
	"log"
	"os"

	socketio "github.com/zhouhui8915/go-socket.io-client"
)

func main() {
	var edgeFqdn string
	flag.StringVar(&edgeFqdn, "edge_fqdn",
		"ggkho8pz7n2vvjqy.bqnp2d2beqol13qn.v1.d.beameio.net", "Edge FQDN")
	flag.Parse()

	opts := &socketio.Options{
		Transport: "websocket",
		Query:     map[string]string{}, // "user": "user", "pwd": "pass"
	}

	// uri := "https://" + edgeFqdn + "/socket.io/"
	uri := "http://" + edgeFqdn + "/socket.io/"

	client, err := socketio.NewClient(uri, opts)
	if err != nil {
		log.Printf("NewClient error: %v\n", err)
		return
	}

	client.On("error", func() {
		log.Printf("on error\n")
	})
	client.On("connection", func() {
		log.Printf("on connect\n")
	})
	client.On("message", func(msg string) {
		log.Printf("on message: %v\n", msg)
	})
	client.On("disconnection", func() {
		log.Printf("on disconnect\n")
	})

	// Custom
	client.On("chat message", func(msg string) {
		log.Printf("on chat message: %v\n", msg)
	})

	reader := bufio.NewReader(os.Stdin)
	for {
		data, _, _ := reader.ReadLine()
		command := string(data)
		client.Emit("chat message", command)
		log.Printf("sent message: %v\n", command)
	}
}
