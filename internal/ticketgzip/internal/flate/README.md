# Ticket DEFLATE writer

deflate.go, deflatefast.go, huffman_bit_writer.go, huffman_code.go and token.go
are unchanged copies of Go 1.21.3 src/compress/flate, covered by the included
Go BSD license. shared.go holds the maxNumLit constant and InternalError type
from inflate.go.

Ticket commitments hash these encoded bytes. Do not update or replace this
writer without verifying it against historical ticket data.
