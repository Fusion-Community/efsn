package datong

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
)

func TestSnapshotRejectsTruncatedCount(t *testing.T) {
	for length := 1; length < 5; length++ {
		for _, spare := range []int{0, 65} {
			t.Run(fmt.Sprintf("length_%d_spare_%d", length, spare), func(t *testing.T) {
				data := make([]byte, length, length+spare)
				data[length-1] = crypto.Keccak256(data[:length-1])[0]
				defer func() {
					if failure := recover(); failure != nil {
						t.Errorf("truncated count panicked instead of returning an error: %v", failure)
					}
				}()
				_, err := newSnapshotWithData(data)
				if err == nil {
					t.Fatal("accepted truncated snapshot count")
				}
			})
		}
	}
}

func TestSnapshotPreservesValidEncoding(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		want *Snapshot
	}{
		{"empty_inventory", []byte{0, 0, 0, 0}, &Snapshot{Retreat: []common.Hash{}, TicketNumber: 0}},
		{"count_only", []byte{0, 0, 0, 26}, &Snapshot{Retreat: []common.Hash{}, TicketNumber: 26}},
		{"selection_retreat", common.FromHex("00000002111111111111111111111111111111111111111111111111111111111111111101222222222222222222222222222222222222222222222222222222222222222202"), &Snapshot{Selected: common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"), Retreat: []common.Hash{common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")}, TicketNumber: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append(append([]byte(nil), test.body...), crypto.Keccak256(test.body)[0])
			snapshot, err := newSnapshotWithData(data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(snapshot.ToShow(), test.want) || !bytes.Equal(snapshot.Bytes(), data) {
				t.Fatalf("valid snapshot changed: %+v", snapshot.ToShow())
			}
		})
	}
}

func TestSnapshotRejectsInvalidFraming(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"checksum", []byte{0, 0, 0, 26, crypto.Keccak256([]byte{0, 0, 0, 26})[0] ^ 1}},
		{"partial_record", append([]byte{0, 0, 0, 26, 1}, crypto.Keccak256([]byte{0, 0, 0, 26, 1})[0])},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newSnapshotWithData(test.data); err == nil {
				t.Fatal("accepted invalid snapshot framing")
			}
		})
	}
}

func FuzzSnapshotFraming(f *testing.F) {
	f.Add([]byte{})
	for length := 0; length <= 4; length++ {
		body := make([]byte, length)
		f.Add(append(body, crypto.Keccak256(body)[0]))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = newSnapshotWithData(data)
		extra := append(make([]byte, 32), data...)
		extra = append(extra, make([]byte, 65)...)
		_, _ = NewSnapshotFromHeader(&types.Header{Extra: extra})
	})
}
