package main

import (
	"fmt"
	"strings"
	"io/ioutil"
	"os"
	"encoding/json"
)

type Identity map[string]string

func NewIdentity(S *Server, in map[string]interface{}) (id Identity, err error) {
	id = make(map[string]string)

	require := map[string]bool {
		"@switch": true,
		"@port": true,
		"@mac": true,
	}

	for k := range in {
		// interpret as string
		val, ok := in[k].(string)
		if !ok { return nil, fmt.Errorf("%s: must be string", k) }
		
		// special checks
		switch k {
		case "@switch", "@port", "@mac", "@ip":
			if strings.Index(val, "..") >= 0 || strings.Index(val, "/") >= 0 {
				return nil, fmt.Errorf("%s: must not contain path elements", k)
			}
			val = strings.ToLower(val)
		}

		// rewrite
		id[k] = val

		// satisfied?
		delete(require, k)
	}

	if len(require) > 0 {
		for k := range require {
			return nil, fmt.Errorf("%s: required key not found", k)
		}
	}

    return
}

func ReadIdentity(S *Server, fh *os.File) (id Identity, err error) {
	jsonb, err := ioutil.ReadAll(fh)
	if err != nil { return }

	var in map[string]interface{}
	err = json.Unmarshal(jsonb, &in)
	if err != nil { return }

	return NewIdentity(S, in)
}

func (id *Identity) JSON() ([]byte, error) {
	return json.MarshalIndent(id, "", "\t")
}
