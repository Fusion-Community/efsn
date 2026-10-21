package ticketgzip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"

	"github.com/FusionFoundation/efsn/v5/internal/ticketgzip/internal/flate"
)

func Encode(payload []byte) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff})
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(payload); err != nil {
		return nil, errors.New("Unable to zip tickets data")
	}
	if err := writer.Close(); err != nil {
		return nil, errors.New("Unable to zip tickets")
	}
	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[:4], crc32.ChecksumIEEE(payload))
	binary.LittleEndian.PutUint32(trailer[4:], uint32(len(payload)))
	buffer.Write(trailer[:])
	return buffer.Bytes(), nil
}
