package blake3

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
	"testing"

	"github.com/bhojpur/crypto/pkg/digest"
	"github.com/bhojpur/crypto/pkg/testdigest"
)

func TestBLAKE3(t *testing.T) {
	testdigest.RunTestCase(t, testdigest.TestCase{
		Input:     "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		Algorithm: "blake3",
		Encoded:   "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
	})
}

func TestBLAKE3Vector(t *testing.T) {
	// From the BLAKE3 test vectors.
	testvector := digest.BLAKE3.FromBytes([]byte{0, 1, 2, 3, 4})
	expected := "blake3:b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"
	if string(testvector) != expected {
		t.Fatalf("Expected: %s; Got: %s", expected, testvector)
	}
}
