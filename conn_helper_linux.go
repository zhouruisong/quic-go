// +build linux

package quic

import "golang.org/x/sys/unix"

const msgTypeIPTOS = unix.IP_TOS

const batchSize = 10 // needs to smaller than MaxUint8 (otherwise the type of ecnConn.readPos has to be changed)
