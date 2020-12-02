package main

import (
	"flag"
	"fmt"
	"os"

	merkleeyes "github.com/melekes/jepsen/merkleeyes"
	"github.com/tendermint/tendermint/abci/server"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
)

var (
	logger = log.NewTMLogger(log.NewSyncWriter(os.Stdout))

	dbDir string
	laddr string
)

func init() {
	flag.StringVar(&dbDir, "dbdir", "", "database directory")
	flag.StringVar(&laddr, "laddr", "unix://data.sock", "listen address")
}

func main() {
	flag.Parse()

	app, err := merkleeyes.New(dbDir, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't create app: %v", err)
		os.Exit(3) // 1 and 2 are reserved (https://tldp.org/LDP/abs/html/exitcodes.html)
	}
	app.SetLogger(logger)

	srv, err := server.NewServer(laddr, "socket", app)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't create server: %v", err)
		os.Exit(4)
	}
	srv.SetLogger(logger.With("module", "abci-server"))

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "can't start server: %v", err)
		os.Exit(5)
	}

	// Stop upon receiving SIGTERM or CTRL-C.
	tmos.TrapSignal(logger, func() {
		// Cleanup
		srv.Stop()
		app.CloseDB()
	})

	// Run forever.
	select {}
}
