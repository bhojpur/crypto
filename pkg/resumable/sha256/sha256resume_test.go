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
	"crypto/rand"
	"crypto/sha256" // To register the stdlib sha224 and sha256 algs.
	"hash"
	"io"
	"testing"

	"github.com/bhojpur/crypto/pkg/resumable"
)

func compareResumableHash(t *testing.T, newResumable func() hash.Hash, newStdlib func() hash.Hash) {
	// Read 3 Kilobytes of random data into a buffer.
	buf := make([]byte, 3*1024)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("unable to load random data: %s", err)
	}

	// Use two Hash objects to consume prefixes of the data. One will be
	// snapshotted and resumed with each additional byte, then both will write
	// that byte. The digests should be equal after each byte is digested.
	resumableHasher := newResumable().(resumable.Hash)
	stdlibHasher := newStdlib()

	// First, assert that the initial distest is the same.
	if !bytes.Equal(resumableHasher.Sum(nil), stdlibHasher.Sum(nil)) {
		t.Fatalf("initial digests do not match: got %x, expected %x", resumableHasher.Sum(nil), stdlibHasher.Sum(nil))
	}

	multiWriter := io.MultiWriter(resumableHasher, stdlibHasher)

	for i := 1; i <= len(buf); i++ {

		// Write the next byte.
		multiWriter.Write(buf[i-1 : i])

		if !bytes.Equal(resumableHasher.Sum(nil), stdlibHasher.Sum(nil)) {
			t.Fatalf("digests do not match: got %x, expected %x", resumableHasher.Sum(nil), stdlibHasher.Sum(nil))
		}

		// Snapshot, reset, and restore the chunk hasher.
		hashState, err := resumableHasher.State()
		if err != nil {
			t.Fatalf("unable to get state of hash function: %s", err)
		}
		resumableHasher.Reset()
		if err := resumableHasher.Restore(hashState); err != nil {
			t.Fatalf("unable to restorte state of hash function: %s", err)
		}
	}
}

func TestResumable(t *testing.T) {
	compareResumableHash(t, New224, sha256.New224)
	compareResumableHash(t, New, sha256.New)
}

func TestResumableRegistered(t *testing.T) {

	for _, hf := range []crypto.Hash{crypto.SHA224, crypto.SHA256} {
		// make sure that the hash gets the resumable version from the global
		// registry in crypto library.
		h := hf.New()

		if rh, ok := h.(resumable.Hash); !ok {
			t.Fatalf("non-resumable hash function registered: %#v %#v", rh, crypto.SHA256)
		}

	}

}
