// Copyright (c) 2018 Awarepoint Corporation. All rights reserved.
// AWAREPOINT PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.

package intelhex

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func decodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestChecksum(t *testing.T) {
	sum := Checksum(decodeHex("0300300002337A"))
	if sum != 0x1E {
		t.Errorf("expected 0x1E but got 0x%02X", checksumError{0x1E, sum})
	}
}

func TestRecordUnmarshalBinary(t *testing.T) {
	var cases = []struct {
		expectErr bool
		data      []byte
		record    Record
	}{
		// Test all record types from https://en.wikipedia.org/wiki/Intel_HEX#Record_types
		{
			false,
			decodeHex("10010000214601360121470136007EFE09D2190140"),
			Record{
				ByteCount:  0x10,
				Address:    0x0100,
				RecordType: RecordTypeData,
				Data:       decodeHex("214601360121470136007EFE09D21901"),
				Checksum:   0x40,
			},
		},
		{
			false,
			decodeHex("00000001FF"),
			Record{
				ByteCount:  0x00,
				Address:    0x0000,
				RecordType: RecordTypeEOF,
				Data:       []byte{},
				Checksum:   0xFF,
			},
		},
		{
			false,
			decodeHex("020000021200EA"),
			Record{
				ByteCount:  0x02,
				Address:    0x0000,
				RecordType: RecordTypeExtSegAddr,
				Data:       []byte{0x12, 0x00},
				Checksum:   0xEA,
			},
		},
		{
			false,
			decodeHex("0400000300003800C1"),
			Record{
				ByteCount:  0x04,
				Address:    0x0000,
				RecordType: RecordTypeStartSegAddr,
				Data:       decodeHex("00003800"),
				Checksum:   0xC1,
			},
		},
		{
			false,
			decodeHex("02000004FFFFFC"),
			Record{
				ByteCount:  0x02,
				Address:    0x0000,
				RecordType: RecordTypeExtLinAddr,
				Data:       decodeHex("FFFF"),
				Checksum:   0xFC,
			},
		},
		{
			false,
			decodeHex("04000005000000CD2A"),
			Record{
				ByteCount:  0x04,
				Address:    0x0000,
				RecordType: RecordTypeStartLinAddr,
				Data:       decodeHex("000000CD"),
				Checksum:   0x2A,
			},
		},

		// Test empty data returns an error
		{
			true,
			[]byte{},
			Record{},
		},

		// Test invalid record type
		{
			true,
			decodeHex("020000061200EA"),
			Record{},
		},

		// Test checksum error
		{
			true,
			decodeHex("04000005000000CD2B"),
			Record{},
		},

		// Test invalid byte counts (!= 0x02) for extended address records
		{
			true,
			decodeHex("040000021200EA"),
			Record{},
		},
		{
			true,
			decodeHex("04000004FFFFFC"),
			Record{},
		},

		// Test byte count is too short
		{
			true,
			decodeHex("03000005000000CD2A"),
			Record{},
		},

		// Test byte count is too long
		{
			true,
			decodeHex("05000005000000CD2A"),
			Record{},
		},

		// Test data is too short
		{
			true,
			decodeHex("040000050000002A"),
			Record{},
		},

		// Test data is too long
		{
			true,
			decodeHex("04000005000000CDDEADBEEF2A"),
			Record{},
		},
	}

	for i, tc := range cases {
		t.Logf("Case %d", i)

		var r Record
		err := (&r).UnmarshalBinary(tc.data)
		if tc.expectErr {
			if err == nil {
				t.Error("expected error")
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			} else {
				if r.ByteCount != tc.record.ByteCount {
					t.Errorf("byte count mismatch: expected=0x%02X, actual=0x%02X", tc.record.ByteCount, r.ByteCount)
				}
				if r.Address != tc.record.Address {
					t.Errorf("address mismatch: expected=0x%04X, actual=0x%04X", tc.record.Address, r.Address)
				}
				if r.RecordType != tc.record.RecordType {
					t.Errorf("record type mismatch: expected=0x%02X, actual=0x%02X", tc.record.RecordType, r.RecordType)
				}
				if !bytes.Equal(r.Data, tc.record.Data) {
					t.Errorf("data mismatch: expected=%X, actual=%X", tc.record.Data, r.Data)
				}
				if r.Checksum != tc.record.Checksum {
					t.Errorf("checksum mismatch: expected=0x%02X, actual=0x%02X", tc.record.Checksum, r.Checksum)
				}
			}
		}
	}
}

func TestScanner(t *testing.T) {
	var cases = []struct {
		expectErr bool
		r         io.Reader
		segments  []Segment
	}{
		{
			expectErr: false,
			r:         strings.NewReader(`:00000001FF`),
			segments:  []Segment{},
		},
		{
			expectErr: false,
			r: strings.NewReader(`
:10010000214601360121470136007EFE09D2190140
:100110002146017E17C20001FF5F16002148011928
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7
:00000001FF`),
			segments: []Segment{
				{0x0100, decodeHex("214601360121470136007EFE09D21901")},
				{0x0110, decodeHex("2146017E17C20001FF5F160021480119")},
				{0x0120, decodeHex("194E79234623965778239EDA3F01B2CA")},
				{0x0130, decodeHex("3F0156702B5E712B722B732146013421")},
			},
		},

		// Extended Segmented (0xFFFF)
		{
			expectErr: false,
			r: strings.NewReader(`
:10010000214601360121470136007EFE09D2190140
:02000002FFFFFE
:100110002146017E17C20001FF5F16002148011928
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7
:00000001FF`),
			segments: []Segment{
				{0x0100, decodeHex("214601360121470136007EFE09D21901")},
				{0xFFFF0 + 0x0110, decodeHex("2146017E17C20001FF5F160021480119")},
				{0xFFFF0 + 0x0120, decodeHex("194E79234623965778239EDA3F01B2CA")},
				{0xFFFF0 + 0x0130, decodeHex("3F0156702B5E712B722B732146013421")},
			},
		},

		// Extended Linear (0xFFFF)
		{
			expectErr: false,
			r: strings.NewReader(`
:10010000214601360121470136007EFE09D2190140
:02000004FFFFFC
:100110002146017E17C20001FF5F16002148011928
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7
:00000001FF`),
			segments: []Segment{
				{0x0100, decodeHex("214601360121470136007EFE09D21901")},
				{0xFFFF0000 + 0x0110, decodeHex("2146017E17C20001FF5F160021480119")},
				{0xFFFF0000 + 0x0120, decodeHex("194E79234623965778239EDA3F01B2CA")},
				{0xFFFF0000 + 0x0130, decodeHex("3F0156702B5E712B722B732146013421")},
			},
		},

		// Fail file missing EOF record
		{
			expectErr: true,
			r: strings.NewReader(`
:10010000214601360121470136007EFE09D2190140
:100110002146017E17C20001FF5F16002148011928
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7`),
			segments: []Segment{
				{0x0100, decodeHex("214601360121470136007EFE09D21901")},
				{0x0110, decodeHex("2146017E17C20001FF5F160021480119")},
				{0x0120, decodeHex("194E79234623965778239EDA3F01B2CA")},
				{0x0130, decodeHex("3F0156702B5E712B722B732146013421")},
			},
		},
	}

	for i, tc := range cases {
		t.Logf("Case %d", i)

		var (
			s        = NewScanner(tc.r)
			err      error
			segments = make([]Segment, 0)
		)

		for s.Scan() {
			segments = append(segments, s.Segment())
		}

		err = s.Err()

		if tc.expectErr {
			if err == nil {
				t.Error("expected error")
			}
			if err == io.EOF {
				t.Error("unexpected EOF")
			}
		} else {
			if err != nil && err != io.EOF {
				t.Errorf("unexpected error: %v", err)
			} else {
				if len(segments) == len(tc.segments) {
					for j := 0; j < len(segments); j++ {
						if segments[j].Address != tc.segments[j].Address {
							t.Errorf("    [segment %d] address mismatch: expected=0x%08X, actual=0x%08X", j, tc.segments[j].Address, segments[j].Address)
						}
						if !bytes.Equal(segments[j].Data, tc.segments[j].Data) {
							t.Errorf("    [segment %d] data mismatch: expected=%X, actual=%X", j, tc.segments[j].Data, segments[j].Data)
						}
					}
				} else {
					t.Errorf("segment length mismatch: expected=%d, actual=%d", len(tc.segments), len(segments))
				}
			}
		}
	}
}
