package main

import (
	"time"
	"io/ioutil"
	"errors"
	"fmt"
	"os"
)

const (
	DB_IDS = "identities"
	DB_DATETIME_FORMAT = "20060102T1504Z"
)

var (
	err_unknown_mac = errors.New("MAC address not authorized on that port")
	err_mac_file = errors.New("DB error for that MAC: should be a directory")
	err_timestamp = errors.New("identity timestamp too old")
	err_downgrade = errors.New("identity downgrade detected")
)

type DB struct {
	S *Server
}

type Profile map[string]interface{}

func NewDB(S *Server) *DB {
	// change CWD to -db
	if err := os.MkdirAll(S.opts.db, 0750); err != nil { dieErr("db", err) }
	if err := os.Chdir(S.opts.db); err != nil { dieErr("db", err) }

	db := &DB{}
	db.S = S

	return db
}

func (db *DB) DevicePath(id Identity) string {
	return fmt.Sprintf("%s/%s/%s/%s",
		DB_IDS, id["@switch"], id["@port"], id["@mac"])
}

func (db *DB) Authorize(id Identity) error {
	path := db.DevicePath(id)
	dbg(3, "db", "%s: checking if exists", path)

	// is MAC authorized on that switch port?
	stat, err := os.Stat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err): return err_unknown_mac
		default: return err
		}
	} else if !stat.IsDir() { return err_mac_file }

	// new keys in id
	new_keys := make(map[string]bool)
	for k := range id { if k[0] != '@' { new_keys[k] = true } }

	// do we already have the identity file?
	pathid := path + "/identity.json"
	fh, err := os.Open(pathid)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			dbg(2, "db", "%s: not seen yet", pathid)
			break
		default:
			return err
		}
	} else { // verify if no downgrade
		old, err := ReadIdentity(db.S, fh)
		if err != nil { return err } // NB: fail hard (deny access on I/O error)

		for k := range old {
	 		switch {
			case k[0] == '@':      // added by ap-switch, ignore
				continue 
			 case old[k] == id[k]: // value did not change
				delete(new_keys, k)
				continue

			case k == "timestamp": // allow forward update
				old_date, err := time.Parse(DB_DATETIME_FORMAT, old["timestamp"])
				if err != nil { return err } // fail hard

				new_date, err := time.Parse(DB_DATETIME_FORMAT, id["timestamp"])
				if err != nil { return err } // fail hard

				// time going backwards?
				if new_date.Before(old_date) {
					return err_timestamp
				} else {
					dbg(2, "db", "%s: timestamp update", pathid)
				}
				
			default:
				return err_downgrade
			}
		}
	}

	// should we store an updated identity file?
	if len(new_keys) > 0 {
		dbg(1, "db", "%s: writing new file", pathid)

		jsonb, err := id.JSON()
		if err == nil { err = ioutil.WriteFile(pathid, jsonb, 0640) }
		if err != nil { dbg(0, "db", "storing the identity failed: %s", err) }
	}

	// TODO: do we have any additional identity elements to add?
	// read path/add.json, use OUI db
	
	return nil
}
