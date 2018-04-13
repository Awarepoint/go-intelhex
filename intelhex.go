// Copyright (c) 2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

// Package intelhex implements an Intel HEX parser.
package intelhex

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Checksum returns the two's complement checksum described here:
// https://en.wikipedia.org/wiki/Intel_HEX#Checksum_calculation
func Checksum(data []byte) byte {
	var sum uint
	for _, b := range data {
		sum += uint(b)
	}
	return byte(^sum + 1)
}

// StartCode is the byte that each record's line is expected to start with.
const StartCode = ':'

const (
	RecordTypeData         = 0x00
	RecordTypeEOF          = 0x01
	RecordTypeExtSegAddr   = 0x02
	RecordTypeStartSegAddr = 0x03
	RecordTypeExtLinAddr   = 0x04
	RecordTypeStartLinAddr = 0x05

	NumRecordTypes = 0x06
)

var EOFRecord = NewRecord(RecordTypeEOF, 0, nil)

type Record struct {
	ByteCount  byte
	Address    uint16
	RecordType byte
	Data       []byte
	Checksum   byte
}

func NewRecord(recordType byte, address uint16, data []byte) (record *Record) {
	record = new(Record)
	record.ByteCount = byte(len(data))
	record.Address = address
	record.RecordType = recordType
	record.Data = make([]byte, len(data))
	copy(record.Data, data)

	record.MarshalBinary()

	return
}

// MarshalBinary encodes a record into a byte slice. It also calculates and fixes
// the record's checksum.
func (x *Record) MarshalBinary() (data []byte, err error) {
	buf := &bytes.Buffer{}

	// Check that the byte count and and data lengths match
	if len(x.Data) != int(x.ByteCount) {
		err = byteCountMismatchError{int(x.ByteCount), len(data)}
	}

	// Verify extended addresses have a byte count of 2
	if x.RecordType == RecordTypeExtSegAddr && x.ByteCount != 0x02 {
		err = fmt.Errorf("expected extended segment address record type to have byte count of 0x02 but got 0x%02X", x.ByteCount)
		return
	}
	if x.RecordType == RecordTypeExtLinAddr && x.ByteCount != 0x02 {
		err = fmt.Errorf("expected extended linear address record type to have byte count of 0x02 but got 0x%02X", x.ByteCount)
		return
	}

	// Encode all the fields
	err = binary.Write(buf, binary.BigEndian, &x.ByteCount)
	if err != nil {
		err = fmt.Errorf("error encoding byte count field: %v", err)
		return
	}
	err = binary.Write(buf, binary.BigEndian, &x.Address)
	if err != nil {
		err = fmt.Errorf("error encoding address field: %v", err)
		return
	}

	if x.RecordType >= NumRecordTypes {
		err = invalidRecordTypeError(x.RecordType)
		return
	}
	err = binary.Write(buf, binary.BigEndian, &x.RecordType)
	if err != nil {
		err = fmt.Errorf("error encoding record type field: %v", err)
		return
	}

	if len(x.Data) > 0 {
		err = binary.Write(buf, binary.BigEndian, &x.Data)
		if err != nil {
			err = fmt.Errorf("error encoding data field: %v", err)
			return
		}
	}

	// Calculate the checksum
	data = buf.Bytes()
	x.Checksum = Checksum(data[0:len(data)])

	// If the checksum is matched then write is as well
	err = binary.Write(buf, binary.BigEndian, &x.Checksum)
	if err != nil {
		err = fmt.Errorf("error encoding checksum field: %v", err)
		return
	}

	data = buf.Bytes()
	return
}

type byteCountMismatchError struct {
	byteCount  int
	dataLength int
}

func (err byteCountMismatchError) Error() string {
	return fmt.Sprintf("byte count was %d but data length was %d", err.byteCount, err.dataLength)
}

// IsChecksumError returns true if the given error was caused by a checksum error.
func IsChecksumError(err error) bool {
	_, ok := err.(checksumError)
	return ok
}

// IsInvalidRecordTypeError returns true if the given error was caused by an
// unsupported record type.
func IsInvalidRecordTypeError(err error) bool {
	_, ok := err.(invalidRecordTypeError)
	return ok
}

// UnmarshalBinary decodes a record from the given data or returns an error.
// The functions IsChecksumError or IsInvalidRecordTypeError can be used to
// determine the type of error.
func (x *Record) UnmarshalBinary(data []byte) (err error) {
	r := bytes.NewReader(data)

	// Decode all the fields
	err = binary.Read(r, binary.BigEndian, &x.ByteCount)
	if err != nil {
		return fmt.Errorf("error decoding byte count field: %v", err)
	}
	err = binary.Read(r, binary.BigEndian, &x.Address)
	if err != nil {
		return fmt.Errorf("error decoding address field: %v", err)
	}

	err = binary.Read(r, binary.BigEndian, &x.RecordType)
	if err != nil {
		return fmt.Errorf("error decoding record type field: %v", err)
	}
	if x.RecordType >= NumRecordTypes {
		return invalidRecordTypeError(x.RecordType)
	}

	// Verify extended addresses have a byte count of 2
	if x.RecordType == RecordTypeExtSegAddr && x.ByteCount != 0x02 {
		return fmt.Errorf("expected extended segment address record type to have byte count of 0x02 but got 0x%02X", x.ByteCount)
	}
	if x.RecordType == RecordTypeExtLinAddr && x.ByteCount != 0x02 {
		return fmt.Errorf("expected extended linear address record type to have byte count of 0x02 but got 0x%02X", x.ByteCount)
	}

	x.Data = make([]byte, x.ByteCount)
	if len(x.Data) > 0 {
		err = binary.Read(r, binary.BigEndian, &x.Data)
		if err != nil {
			return fmt.Errorf("error decoding data field: %v", err)
		}
	}
	err = binary.Read(r, binary.BigEndian, &x.Checksum)
	if err != nil {
		return fmt.Errorf("error decoding checksum field: %v", err)
	}

	if r.Len() != 0 {
		return fmt.Errorf("unexpected %d bytes left", r.Len())
	}

	// Validate the checksum
	calculated := Checksum(data[0 : len(data)-1])
	if calculated != x.Checksum {
		return checksumError{x.Checksum, calculated}
	}

	return
}

type checksumError struct {
	expected   byte
	calculated byte
}

func (err checksumError) Error() string {
	return fmt.Sprintf("expected checksum 0x%02X but calculated 0x%02X", err.expected, err.calculated)
}

type invalidRecordTypeError byte

func (err invalidRecordTypeError) Error() string {
	return fmt.Sprintf("invalid record type 0x%02X", byte(err))
}

type Scanner struct {
	scanner  *bufio.Scanner
	firstErr error

	extendedSegmentedAddressBase uint32
	extendedLinearAddressBase    uint32

	segment Segment
}

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{
		scanner: bufio.NewScanner(r),
	}
}

func (s *Scanner) Err() error {
	if s.firstErr != nil {
		return s.firstErr
	}
	return s.scanner.Err()
}

func (s *Scanner) Scan() bool {
	if s.firstErr != nil {
		return false
	}

	for s.scanner.Scan() {
		hexData := s.scanner.Bytes()
		if len(hexData) == 0 {
			continue // skip empty lines
		}

		// Check for the start code
		if hexData[0] != StartCode {
			s.firstErr = fmt.Errorf("expected start code %c but got %c", StartCode, hexData[0])
			return false
		}

		src := hexData[1:]
		dst := make([]byte, hex.DecodedLen(len(src)))
		_, s.firstErr = hex.Decode(dst, src)
		if s.firstErr != nil {
			return false
		}

		// Decode the record
		var record Record
		s.firstErr = (&record).UnmarshalBinary(dst)
		if s.firstErr != nil {
			return false
		}

		switch record.RecordType {
		case RecordTypeData:
			var addressBase uint32

			// Only one should be non-zero at a time so the order shouldn't matter
			if s.extendedSegmentedAddressBase != 0 {
				addressBase = s.extendedSegmentedAddressBase
			}
			if s.extendedLinearAddressBase != 0 {
				addressBase = s.extendedLinearAddressBase
			}

			s.segment.Address = addressBase + uint32(record.Address)

			s.segment.Data = make([]byte, len(record.Data))
			copy(s.segment.Data, record.Data)

			// Return this segment, skipping any error checks
			return true

		case RecordTypeEOF:
			return false // return with no error

		case RecordTypeExtSegAddr:
			s.extendedSegmentedAddressBase = ((uint32(record.Data[0]) << 8) | uint32(record.Data[1])) << 4
			s.extendedLinearAddressBase = 0

		case RecordTypeExtLinAddr:
			s.extendedSegmentedAddressBase = 0
			s.extendedLinearAddressBase = ((uint32(record.Data[0]) << 8) | uint32(record.Data[1])) << 16
		}
	}

	s.firstErr = s.scanner.Err()
	if s.firstErr == nil {
		s.firstErr = fmt.Errorf("unexpected EOF")
	}

	return false
}

func (s *Scanner) Segment() Segment {
	return s.segment
}

type Segment struct {
	Address uint32
	Data    []byte
}

type SegmentSlice []*Segment

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

func (s SegmentSlice) Write(w io.Writer) error {
	// Keep track of the address offset
	var extendedLinearAddressBase uint32

	for _, seg := range s {
		// Check if we need to output a new address base
		base := seg.Address >> 16
		if base != extendedLinearAddressBase {
			// Save the base so we don't write the extended record multiple times
			extendedLinearAddressBase = base

			// Write the
			record := NewRecord(RecordTypeExtLinAddr, 0, []byte{
				byte(base >> 8),
				byte(base >> 0),
			})
			d, err := record.MarshalBinary()
			if err != nil {
				return err
			}
			fmt.Fprint(w, string(StartCode))
			_, err = w.Write([]byte(strings.ToUpper(hex.EncodeToString(d))))
			if err != nil {
				return err
			}
			fmt.Fprintln(w, "")
		}

		// Write the data record
		record := NewRecord(RecordTypeData, uint16(seg.Address&0xFFFF), seg.Data)
		d, err := record.MarshalBinary()
		if err != nil {
			return err
		}
		fmt.Fprint(w, string(StartCode))
		_, err = w.Write([]byte(strings.ToUpper(hex.EncodeToString(d))))
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "")
	}

	// Write the EOF record
	d, err := EOFRecord.MarshalBinary()
	if err != nil {
		return err
	}
	fmt.Fprint(w, string(StartCode))
	_, err = w.Write([]byte(strings.ToUpper(hex.EncodeToString(d))))
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "")

	return nil
}

func (s SegmentSlice) WriteFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Write(f)
}
