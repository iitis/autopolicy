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
	"fmt"
	"strings"
	"io/ioutil"
	"os"
	"encoding/json"
)

type Identity map[string]string

var required = []string{ "@switch", "@port", "@mac" }

func (S *Server) NewIdentity(in map[string]interface{}) (id Identity, err error) {
	id = make(map[string]string)
	for k := range in {
		var val string

		// interpret as string
		switch v := in[k].(type) {
		case string: val = v
		default:     val = fmt.Sprintf("%v", v)
		}
		
		// special checks
		switch k {
		case "@switch", "@port", "@mac", "@ip", "$version":
			if strings.Index(val, "..") >= 0 || strings.Index(val, "/") >= 0 {
				return nil, fmt.Errorf("%s: must not contain path elements", k)
			}
			val = strings.ToLower(val)
		}

		// rewrite
		id[k] = val
	}

    return id, nil
}

func (id Identity) CheckRequired() error {
	for _,k := range required {
		if _, ok := id[k]; !ok {
			return fmt.Errorf("%s: required key not found", k)
		}
	}
	return nil
}

func (S *Server) ReadIdentity(fh *os.File) (id Identity, err error) {
	jsonb, err := ioutil.ReadAll(fh)
	if err != nil { return }

	var in map[string]interface{}
	err = json.Unmarshal(jsonb, &in)
	if err != nil { return }

	return S.NewIdentity(in)
}

func (id *Identity) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(id, "", "\t")
	if err == nil {
		return append(out, '\n'), nil
	} else {
		return nil, err
	}
}
