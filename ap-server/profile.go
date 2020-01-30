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
	"time"
	"io/ioutil"
	"os"
	"encoding/json"
)

type Profile map[string]interface{}

func (S *Server) NewProfile(in map[string]interface{}, source string) (pf Profile, err error) {
	if in == nil {
		pf = make(Profile)
	} else {
		// TODO: should verify?
		pf = in
	}

	// add @timestamp, @source
	pf["@timestamp"] = time.Now().Unix()
	pf["@source"] = source

    return
}

func (S *Server) ReadProfile(fh *os.File) (Profile, error) {
	pf := make(map[string]interface{})

	jsonb, err := ioutil.ReadAll(fh)
	if err != nil { return pf, err }

	// NB: no verification
	err = json.Unmarshal(jsonb, &pf)
	return pf, err
}

func (pf *Profile) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(pf, "", "\t")
	if err == nil {
		return append(out, '\n'), nil
	} else {
		return nil, err
	}
}
