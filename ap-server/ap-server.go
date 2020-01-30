package main

import (
	"sync"
	"flag"
	"os"
	"context"
)

const (
	VERSION = "0.1"
)

type Server struct {
	ctx      context.Context
	wg       sync.WaitGroup
	
	hostname string
	opts struct {
		dbg            int
		me             string
		//--
		http           string
		db             string
		auto           bool
		fix            bool
	}

	api     *Api
	db      *DB
}

func main() {
	var err error

	S := &Server{}
	S.ctx = context.Background()
	S.hostname, err = os.Hostname()
	if err != nil { dieErr("main", err) }

	// command-line args
	flag.IntVar(&S.opts.dbg, "dbg", 2, "debugging level")
	flag.StringVar(&S.opts.me, "me", S.hostname, "my identity, e.g. name of this host")
	flag.StringVar(&S.opts.http, "http", ":30000", "listen on given HTTP endpoint")
	flag.StringVar(&S.opts.db, "db", "./db", "path to filesystem database")
	flag.BoolVar(&S.opts.auto, "auto", true, "automatically add first seen MAC on a port")
	flag.BoolVar(&S.opts.fix, "fix", true, "fix missing keys in profiles (use old values)")
	flag.Parse()
	dbgSet(S.opts.dbg)

	S.db = NewDB(S)
	S.api = NewApi(S)
	if len(S.opts.http) > 0 {
		S.wg.Add(1)
		go S.api.ServeHttp(S.opts.http)
	}

	S.wg.Wait()
}
