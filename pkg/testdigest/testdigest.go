package testdigest

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

// testdigest is a separate package, because it has some testing utilities in it that may be useful
// to other internal Algorithm implementors.
//
// It is not a stable interface and not meant for consumption outside of digest developers.

import (
	"testing"

	pkgdigest "github.com/bhojpur/crypto/pkg/digest"
)

type TestCase struct {
	// Input the formal format of the hash, for example sha256:e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b
	Input string
	// If err is non-nil, then the parsing of Input is expected to return this error
	Err error
	// Algorithm should be an available or registered algorithm
	Algorithm pkgdigest.Algorithm
	// Encoded is the the encoded portion of the digest to expect, for example e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b
	Encoded string
}

func RunTestCase(t *testing.T, testcase TestCase) {
	digest, err := pkgdigest.Parse(testcase.Input)
	if err != testcase.Err {
		t.Fatalf("error differed from expected while parsing %q: %v != %v", testcase.Input, err, testcase.Err)
	}

	if testcase.Err != nil {
		return
	}

	if digest.Algorithm() != testcase.Algorithm {
		t.Fatalf("incorrect Algorithm for parsed digest: %q != %q", digest.Algorithm(), testcase.Algorithm)
	}

	if digest.Encoded() != testcase.Encoded {
		t.Fatalf("incorrect hex for parsed digest: %q != %q", digest.Encoded(), testcase.Encoded)
	}

	// Parse string return value and check equality
	newParsed, err := pkgdigest.Parse(digest.String())

	if err != nil {
		t.Fatalf("unexpected error parsing Input %q: %v", testcase.Input, err)
	}

	if newParsed != digest {
		t.Fatalf("expected equal: %q != %q", newParsed, digest)
	}

	newFromHex := pkgdigest.NewDigestFromEncoded(newParsed.Algorithm(), newParsed.Encoded())
	if newFromHex != digest {
		t.Fatalf("%v != %v", newFromHex, digest)
	}
}

func RunTestCases(t *testing.T, testcases []TestCase) {
	for _, testcase := range testcases {
		t.Run(testcase.Input, func(t *testing.T) {
			RunTestCase(t, testcase)
		})
	}
}
