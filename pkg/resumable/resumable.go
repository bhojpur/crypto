package resumable

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

// Package resumable registers resumable versions of hash functions. Resumable
// varieties of hash functions are available via the standard crypto package.
// Support can be checked by type assertion against the resumable.Hash
// interface.
//
// While one can use these sub-packages directly, it makes more sense to
// register them using side-effect imports:
//
// 	import _ "github.com/bhojpur/crypto/pkg/resumable/sha256"
//
// This will make the resumable hashes available to the application through
// the standard crypto package. For example, if a new sha256 is required, one
// should use the following:
//
// 	h := crypto.SHA256.New()
//
// Such a features allows one to control the inclusion of resumable hash
// support in a single file. Applications that require the resumable hash
// implementation can type switch to detect support, while other parts of the
// application can be completely oblivious to the presence of the alternative
// hash functions.
//
// Also note that the implementations available in this package are completely
// untouched from their Go counterparts in the standard library. Only an extra
// file is added to each package to implement the extra resumable hash
// functions.

import (
	"fmt"
	"hash"
)

var (
	// ErrBadState is returned if Restore fails post-unmarshaling validation.
	ErrBadState = fmt.Errorf("bad hash state")
)

// Hash is the common interface implemented by all resumable hash functions.
type Hash interface {
	hash.Hash

	// Len returns the number of bytes written to the Hash so far.
	Len() int64

	// State returns a snapshot of the state of the Hash.
	State() ([]byte, error)

	// Restore resets the Hash to the given state.
	Restore(state []byte) error
}
