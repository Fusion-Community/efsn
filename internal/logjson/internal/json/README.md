# FSN log JSON encoder

encode.go, fold.go, indent.go, scanner.go, tables.go and tags.go are unchanged
copies of Go 1.21.3 src/encoding/json, covered by the included Go BSD license.
shared.go holds the Number type and numberType from decode.go.

FSN call logs written with this encoder are hashed into receipt roots. Do not
update or replace it without verifying it against historical receipts.
