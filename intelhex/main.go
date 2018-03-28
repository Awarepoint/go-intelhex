// Copyright (c) 2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/awarepoint/go-intelhex"
)

func main() {
	flag.Parse()

	var (
		argSrc  = flag.Arg(0)
		argDest = flag.Arg(1)

		src io.Reader = os.Stdin
		dst io.Writer = os.Stdout
	)

	if argSrc != "" {
		f, err := os.Open(argSrc)
		if err != nil {
			fatalf("Error opening source file: %v\n", err)
		}
		defer f.Close()
		src = f
	}

	var (
		scanner  = intelhex.NewScanner(src)
		segments = make([]*intelhex.Segment, 0)
	)

	// Scan all segments
	for scanner.Scan() {
		segment := scanner.Segment()
		segments = append(segments, &segment)
	}
	if err := scanner.Err(); err != nil {
		fatalf("Error scanning source: %v\n", err)
	}

	if len(segments) == 0 {
		fatalf("No segments found.\n")
	}

	// Sort the segments by address
	sort.Sort(SegmentSlice(segments))

	var (
		sa  = segments[0].Address
		buf = make([]byte, SegmentSlice(segments).Size())
	)

	// Fill the buffer with 0xFF
	for i := 0; i < len(buf); i++ {
		buf[i] = 0xFF
	}

	for _, s := range segments {
		copy(buf[s.Address-sa:], s.Data)
	}

	if argDest != "" {
		f, err := os.Create(argDest)
		if err != nil {
			fatalf("Error opening source file: %v\n", err)
		}
		defer f.Close()
		dst = f
	}

	n, err := dst.Write(buf)
	if n != len(buf) {
		fatalf("Write to destination did not complete.\n")
	}
	if err != nil {
		fatalf("Error writing to destination: %v\n", err)
	}
}

type SegmentSlice []*intelhex.Segment

func (s SegmentSlice) Len() int           { return len(s) }
func (s SegmentSlice) Less(i, j int) bool { return s[i].Address < s[j].Address }
func (s SegmentSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s SegmentSlice) Size() uint32 {
	if len(s) == 0 {
		return 0
	}
	if len(s) == 1 {
		return uint32(len(s[0].Data))
	}
	var (
		fs = s[0]
		ls = s[len(s)-1]
	)
	return (ls.Address + uint32(len(ls.Data))) - fs.Address
}

func fatalf(format string, args ...interface{}) {
	infof(format, args...)
	os.Exit(1)
}

func infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}
