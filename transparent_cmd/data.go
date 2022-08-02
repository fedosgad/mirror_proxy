package main

import (
	"encoding/hex"
	"fmt"
	"io"
)

func dumpData(r io.Reader, source string, id int) {
	data := make([]byte, 512)
	for {
		n, err := r.Read(data)
		if n > 0 {
			// hex.Dump + screen output slows things down badly, up to a 5x slow-down
			// best to dump to file and view with tail -f
			// best yet is to only view the file after the transfer completes
			fmt.Printf("From %s [%d]:\n", source, id)
			fmt.Println(hex.Dump(data[:n]))
		}
		if err != nil && err != io.EOF {
			fmt.Printf("unable to read data %v", err)
			break
		}
		if n == 0 {
			break
		}
	}
}

func discardData(r io.Reader) {
	io.Copy(io.Discard, r)
}
