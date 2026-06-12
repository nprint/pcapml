// SPDX-License-Identifier: Apache-2.0

package pcapng

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func testDataPath(name string) string {
	return filepath.Join("..", "..", "test", name)
}

func TestReaderSampleTest(t *testing.T) {
	path := testDataPath("sample-test/test.pcapng")
	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()

	var (
		shbCount, idbCount, epbCount int
		commentsFound                int
	)

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read block: %v", err)
		}

		switch b.Type {
		case SectionHeaderType:
			shbCount++
		case InterfaceDescType:
			idbCount++
			if b.LinkType == 0 {
				t.Error("IDB link type is 0")
			}
		case EnhancedPacketType:
			epbCount++
			if b.CapLen == 0 {
				t.Error("EPB cap_len is 0")
			}
			if len(b.PacketData) == 0 {
				t.Error("EPB packet data is empty")
			}
			if b.Comment != "" {
				commentsFound++
				sid := b.SampleID()
				label := b.Label()
				if sid == "" {
					t.Errorf("empty sample ID in comment %q", b.Comment)
				}
				if label == "" {
					t.Errorf("empty label in comment %q", b.Comment)
				}
			}
		}
	}

	if shbCount != 1 {
		t.Errorf("expected 1 SHB, got %d", shbCount)
	}
	if idbCount < 1 {
		t.Errorf("expected at least 1 IDB, got %d", idbCount)
	}
	if epbCount != 151 {
		t.Errorf("expected 151 EPBs, got %d", epbCount)
	}
	if commentsFound != 151 {
		t.Errorf("expected 151 comments, got %d", commentsFound)
	}
}

func TestReaderTimestamp(t *testing.T) {
	path := testDataPath("sample-test/test.pcapng")
	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()

	for {
		b, err := r.ReadBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read block: %v", err)
		}
		if b.Type == EnhancedPacketType {
			ts := b.Timestamp()
			if ts == 0 {
				t.Error("EPB timestamp is 0")
			}
			return // just check the first packet
		}
	}
	t.Error("no EPB blocks found")
}

func TestCommentVal(t *testing.T) {
	cases := []struct {
		comment string
		key     string
		want    string
	}{
		{"s=42,proc=firefox,dir=lan2wan", "s", "42"},
		{"s=42,proc=firefox,dir=lan2wan", "proc", "firefox"},
		{"s=42,proc=firefox,dir=lan2wan", "dir", "lan2wan"},
		{"s=42,proc=firefox,dir=lan2wan,dst=example.com", "dst", "example.com"},
		{"s=42,proc=firefox,dir=lan2wan", "dst", ""},
		{"s=42,proc=firefox,dir=lan2wan", "missing", ""},
		{"", "s", ""},
		{"s=0", "s", "0"},
		{"s=,proc=test", "s", ""},
	}
	for _, tc := range cases {
		got := CommentVal(tc.comment, tc.key)
		if got != tc.want {
			t.Errorf("CommentVal(%q, %q) = %q, want %q", tc.comment, tc.key, got, tc.want)
		}
	}
}

func TestSampleIDAndLabel(t *testing.T) {
	cases := []struct {
		comment  string
		wantSID  string
		wantLabel string
	}{
		// Keyed format
		{"s=42,proc=firefox,dir=lan2wan", "42", "firefox"},
		{"s=7,dir=wan2lan,dst=youtube.com", "7", "youtube.com"},
		// Legacy positional format
		{"123,myapp,extra", "123", "myapp"},
		{"456,single", "456", "single"},
		// Edge cases
		{"", "", ""},
	}
	for _, tc := range cases {
		b := &Block{Comment: tc.comment}
		if got := b.SampleID(); got != tc.wantSID {
			t.Errorf("SampleID(%q) = %q, want %q", tc.comment, got, tc.wantSID)
		}
		if got := b.Label(); got != tc.wantLabel {
			t.Errorf("Label(%q) = %q, want %q", tc.comment, got, tc.wantLabel)
		}
	}
}

func TestReaderInvalidFile(t *testing.T) {
	_, err := NewReader("/nonexistent/file.pcapng")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReaderEmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "pcapml-test-*.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	r, err := NewReader(f.Name())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()

	_, err = r.ReadBlock()
	if err != io.EOF {
		t.Errorf("expected EOF for empty file, got %v", err)
	}
}
