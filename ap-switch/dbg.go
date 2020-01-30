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
	"os"
	"log"
)

var (
	dbgLevel int
	dbgLogger *log.Logger
)

func dbgSet(lvl int) {
	dbgLevel = lvl
}

func dbg(lvl int, where string, fmt string, v ...interface{}) {
	if lvl <= dbgLevel {
		dbgLogger.Printf(where + ": " + fmt + "\n", v...)
	}
}

func dbgErr(lvl int, where string, err error) {
	if lvl <= dbgLevel {
		dbgLogger.Printf("%s: error: %s\n", where, err.Error())
	}
}

func die(where string, fmt string, v ...interface{}) {
	dbgLogger.Fatalf(where + ": " + fmt + "\n", v...)
}

func dieErr(where string, err error) {
	dbgLogger.Fatalf("%s: fatal error: %s\n", where, err.Error())
}

func E(format string, v ...interface{}) error {
	return fmt.Errorf(format, v...)
}

func init() {
	dbgLogger = log.New(os.Stderr, "", log.LstdFlags | log.LUTC)
}
