/*
 * Autopolicy PoC
 * Copyright (C) 2019-2020 IITiS PAN Gliwice <https://www.iitis.pl/>
 * Author: Pawel Foremski <pjf@iitis.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"encoding/json"
	"net/http"
	"context"
	"bytes"
	"time"
	"strings"
	"io/ioutil"
	"errors"
	"fmt"
	"os"
)

const (
	DB_IDS = "identities"
	DB_PFS = "profiles"

	PF_PROTO = "http://"  // FIXME: use https://
	PF_CACHE = 60 * 15    // cache profiles for 15 minutes

	HTTP_TIMEOUT = 10e9   // in nanoseconds
)

var (
	err_unknown_mac = errors.New("MAC address not authorized on that port")
	err_mac_file = errors.New("DB error for that MAC: should be a directory")
	err_downgrade = errors.New("identity downgrade detected")
	err_http_200 = errors.New("HTTP status code != 200")

	pf_query = [...]string{ "manufacturer", "device", "revision", "$version" }
)

type DB struct {
	S *Server
}

func NewDB(S *Server) *DB {
	// change CWD to -db
	if err := os.MkdirAll(S.opts.db, 0750); err != nil { dieErr("db", err) }
	if err := os.Chdir(S.opts.db); err != nil { dieErr("db", err) }

	db := &DB{}
	db.S = S

	return db
}

func (db *DB) Tag(id Identity) string {
	return fmt.Sprintf("%s/%s/%s", id["@switch"], id["@port"], id["@mac"])
}

func (db *DB) MacPath(id Identity) string {
	return fmt.Sprintf("%s/%s/%s/%s", DB_IDS, id["@switch"], id["@port"], id["@mac"])
}

func (db *DB) PortPath(id Identity) string {
	return fmt.Sprintf("%s/%s/%s", DB_IDS, id["@switch"], id["@port"])
}

func (db *DB) ProfileDir(qstring string) string {
	return fmt.Sprintf("%s/%s", DB_PFS, qstring)
}

func (db *DB) ProfilePath(qstring string, file string) string {
	return fmt.Sprintf("%s/%s/%s", DB_PFS, qstring, file)
}

func (db *DB) ProfileQuery(url string, qstring string) string {
	return fmt.Sprintf("%s/.autopolicy/%s/profile.json", url, qstring)
}

// Verify implements identity verification
//
// First, it will check if we either haven't seen any identity for that device yet, or - if we had -
// it will verify that the identity is not downgraded vs. what has already been seen.
//
// Second (TODO), it will supplement the identity with any additional keys set by the system
// administrator (add.json, set.json, del.json)
//
func (db *DB) Verify(id Identity) (Identity, error) {
	// full path to MAC
	path := db.MacPath(id)

	tag := db.Tag(id)
	dbg(3, "db", "%s: veryfing id %#v", tag, id)

	// is MAC authorized on that switch port?
	checkpath: switch stat, err := os.Stat(path); {
	case err == nil: // path exists, just make sure it's a directory
		if !stat.IsDir() { return nil, err_mac_file }

	case os.IsNotExist(err): // doesn't exist
		// should we automatically add first MAC on that switch port?
		if db.S.opts.auto {
			switch files, err := ioutil.ReadDir(db.PortPath(id)); { // port dir exists?
			case err == nil: // yes, but...
				if len(files) == 0 { // empty? try to create the MAC dir
					err = os.Mkdir(path, 0755)
					if err != nil { return nil, err } // OS error?
					dbg(4, "db", "%s: first MAC on existing port -> auto-add", tag)
					break checkpath  // created, good to go!
				}

			case os.IsNotExist(err): // doesn't exist, try to create MAC dir
				err = os.MkdirAll(path, 0755)
				if err != nil { return nil, err } // OS error?
				dbg(4, "db", "%s: first MAC on non-existing port -> auto-add", tag)
				break checkpath  // created, good to go!

			default: return nil, err // OS error?
			}
		}
		
		// nah, block this MAC
		return nil, err_unknown_mac
		
	default: return nil, err // OS error?
	}

	// collect all keys in the submitted id
	todo := make(map[string]bool)
	for k := range id { if k[0] != '@' { todo[k] = true } }

	// do we already have the identity file?
	pathid := path + "/identity.json"
	fh, err := os.Open(pathid)
	if err != nil {
		switch {
		case os.IsNotExist(err): break // first identity seen so far
		default: return nil, err       // NB: fail hard (deny access on I/O error)
		}
	} else { // verify if no downgrade
		defer fh.Close()
		old, err := db.S.ReadIdentity(fh)
		if err != nil { return nil, err } // NB: fail hard (deny access on I/O error)

		// go through all already stored identity keys
		for k, oldval := range old {
			// internal key, added by ap-switch, ignore
			if k[0] == '@' { continue }

	 		switch newval, still_there := id[k]; {
			case !still_there:     // key is gone, downgrade detected!
				if db.S.opts.fix {
					dbg(4, "db", "%s: missing key '%s', will fix: use old value '%s'",
						tag, k, oldval)
					id[k] = oldval
					delete(todo, k)
				} else {
					dbg(2, "db", "%s: downgrade of '%s': old value '%s', now missing",
						tag, k, oldval)
					return nil, err_downgrade
				}
			case oldval == newval: // value the same as already seen, OK!
				delete(todo, k)
				continue
			case k[0] == '$': // allow update after lexicographical check
				if newval < oldval {
					dbg(2, "db", "%s: downgrade of '%s': old '%s' bigger than new '%s'",
						tag, k, oldval, newval)
					return nil, err_downgrade
				} else {
					dbg(2, "db", "%s: update of '%s': old '%s' smaller than new '%s'",
						tag, k, oldval, newval)
				}
			default: // key value changed, downgrade detected!
				dbg(2, "db", "%s: downgrade of '%s': old '%s' vs. new '%s'",
					tag, k, oldval, newval)
				return nil, err_downgrade
			}
		}
	}

	// should we store an updated identity file?
	if len(todo) > 0 {
		dbg(1, "db", "%s: writing new identity file", tag)

		jsonb, err := id.JSON()
		if err == nil { err = ioutil.WriteFile(pathid, jsonb, 0640) }
		if err != nil { dbg(0, "db", "storing the identity failed: %s", err) }
	}

	// TODO: do we have any additional identity elements to add?
	// e.g. read path/(../)add.json, use the OUI db
	
	return id, nil
}

// Authorize fetches the traffic profile for given (verified) identity
func (db *DB) Authorize(id Identity) (pf Profile, err error) {
	tag := "db: " + db.Tag(id)

	// TODO: use external API if requested

	// get the URL and validate it
	url, has_url := id["url"]
	if has_url {
		url = strings.TrimRight(url, "/")
		if len(url) <= len(PF_PROTO) || url[:len(PF_PROTO)] != PF_PROTO {
			dbg(3, tag, "invalid url in identity: %s", url)
			has_url = false
		}
	}

	// build queries for decreasing level of detail
	query := make([]string, len(pf_query))
	read_from := ""
	rebuild: for i := len(pf_query); i >= 0 && len(read_from) == 0; i-- {
		// collect the query values
		query = query[0:i]
		for j := i - 1; j >= 0; j-- {
			if v, ok := id[pf_query[j]]; ok && len(v) > 0 {
				query[j] = escape(v)
			} else {
				continue rebuild
			}
		}

		// use it
		qstring := strings.Join(query, "/")
		pfpath  := db.ProfilePath(qstring, "profile.json")

		// check if a recent copy is in the local db
		stat, err := os.Stat(pfpath)
		if err == nil {
			read_from = pfpath // NB: will use it anyway if can't fetch
			if time.Now().Unix() - stat.ModTime().Unix() < PF_CACHE { break }
		} else {
			// make sure the directory exists
			os.MkdirAll(db.ProfileDir(qstring), 0755)
		}

		// try to fetch it & store on disk
		if has_url {
			// GET
			src := db.ProfileQuery(url, qstring)
			pfbytes, status, err := db.S.http_get(src)
			if err != nil {
				dbg(3, tag, "HTTP error: %s", err)
				continue
			} else if status == 404 {
				// NB! special case: delete local file
				if len(read_from) > 0 {
					dbg(3, tag, "removing local copy of profile, %s", read_from)
					os.Remove(read_from)
					read_from = ""
				}
				continue
			} else if status != 200 {
				dbg(3, tag, "HTTP status %d", status)
				continue
			}

			// parse
			in := make(map[string]interface{})
			err = json.Unmarshal(pfbytes, &in)
			if err != nil { dbg(3, tag, "JSON error: %s", err); continue }

			// verify & ammend
			pf, err = db.S.NewProfile(in, src)
			if err != nil { dbg(3, tag, "profile error: %s", err); continue }

			// write to disk
			jsonb, err := pf.JSON()
			if err == nil { err = ioutil.WriteFile(pfpath, jsonb, 0640) }
			if err != nil { dbg(2, tag, "storing profile failed: %s", err) }

			// ready for use!
			dbg(3, tag, "fetched new profile from %s", src)
			return pf, nil
		}
	}

	// should read from disk?
	if len(read_from) > 0 {
		dbg(3, tag, "reading profile from %s", read_from)

		fh, err := os.Open(read_from)
		if err != nil { return nil, err }
		defer fh.Close()

		pf, err = db.S.ReadProfile(fh)
		if err != nil { return nil, err }
	}

	// handle empty profile
	if len(pf) == 0 {
		dbg(3, tag, "using empty profile")
		pf, err = db.S.NewProfile(nil, "")
		pf["@empty"] = true
	}

	return
}

// escape string val so it's safe to use in a URL
func escape(val string) string {
	var b bytes.Buffer

	lu := false
	for _,r := range val {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32) // make lowercase
			lu = false
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
			lu = false
		default:
			if lu { continue }
			b.WriteRune('_')
			lu = true
		}
	}

	return string(bytes.Trim(b.Bytes(), "_"))
}

func (S *Server) http_get(url string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(S.ctx, HTTP_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return nil, -1, err }

	// send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, -1, err }
	defer resp.Body.Close()

	// read all
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil { return nil, -1, err }

	return bytes, resp.StatusCode, nil
}
