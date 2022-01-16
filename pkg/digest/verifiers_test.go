package digest

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
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestDigestVerifier(t *testing.T) {
	p := make([]byte, 1<<20)
	rand.Read(p)
	digest := FromBytes(p)

	verifier := digest.Verifier()

	io.Copy(verifier, bytes.NewReader(p))

	if !verifier.Verified() {
		t.Fatalf("bytes not verified")
	}
}

// TestVerifierUnsupportedDigest ensures that unsupported digest validation is
// flowing through verifier creation.
func TestVerifierUnsupportedDigest(t *testing.T) {
	for _, testcase := range []struct {
		Name     string
		Digest   Digest
		Expected interface{} // expected panic target
	}{
		{
			Name:     "Empty",
			Digest:   "",
			Expected: "no ':' separator in digest \"\"",
		},
		{
			Name:     "EmptyAlg",
			Digest:   ":",
			Expected: "empty digest algorithm, validate before calling Algorithm.Hash()",
		},
		{
			Name:     "Unsupported",
			Digest:   Digest("bean:0123456789abcdef"),
			Expected: "bean not available (make sure it is imported)",
		},
		{
			Name:     "Garbage",
			Digest:   Digest("sha256-garbage:pure"),
			Expected: "sha256-garbage not available (make sure it is imported)",
		},
	} {
		t.Run(testcase.Name, func(t *testing.T) {
			expected := testcase.Expected
			defer func() {
				recovered := recover()
				if !reflect.DeepEqual(recovered, expected) {
					t.Fatalf("unexpected recover: %v != %v", recovered, expected)
				}
			}()

			_ = testcase.Digest.Verifier()
		})
	}
}
