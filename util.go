package ntlmssp

import "bytes"

func concat(bs ...[]byte) []byte {
	return bytes.Join(bs, nil)
}
