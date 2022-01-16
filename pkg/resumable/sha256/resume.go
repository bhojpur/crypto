package sha256

// Copyright (c) 2018 Bhojpur Consulting Private Limited, India. All rights reserved.

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import (
	"bytes"
	"crypto"
	"encoding/gob"

	"github.com/bhojpur/crypto/pkg/resumable"
	// import to ensure that our init function runs after the standard package
	_ "crypto/sha256"
)

// Len returns the number of bytes which have been written to the digest.
func (d *digest) Len() int64 {
	return int64(d.len)
}

// State returns a snapshot of the state of the digest.
func (d *digest) State() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	function := crypto.SHA256
	if d.is224 {
		function = crypto.SHA224
	}

	// We encode this way so that we do not have
	// to export these fields of the digest struct.
	vals := []interface{}{
		d.h, d.x, d.nx, d.len, function,
	}

	for _, val := range vals {
		if err := encoder.Encode(val); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Restore resets the digest to the given state.
func (d *digest) Restore(state []byte) error {
	decoder := gob.NewDecoder(bytes.NewReader(state))

	var function uint

	// We decode this way so that we do not have
	// to export these fields of the digest struct.
	vals := []interface{}{
		&d.h, &d.x, &d.nx, &d.len, &function,
	}

	for _, val := range vals {
		if err := decoder.Decode(val); err != nil {
			return err
		}
	}

	switch crypto.Hash(function) {
	case crypto.SHA224:
		d.is224 = true
	case crypto.SHA256:
		d.is224 = false
	default:
		return resumable.ErrBadState
	}

	return nil
}
