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
	"crypto"
	"crypto/rand"
	"flag"
	"fmt"
	"strings"
	"testing"
)

func TestFlagInterface(t *testing.T) {
	var (
		alg     Algorithm
		flagSet flag.FlagSet
	)

	flagSet.Var(&alg, "algorithm", "set the digest algorithm")
	for _, testcase := range []struct {
		Name     string
		Args     []string
		Err      error
		Expected Algorithm
	}{
		{
			Name: "Invalid",
			Args: []string{"-algorithm", "bean"},
			Err:  ErrDigestUnsupported,
		},
		{
			Name:     "Default",
			Args:     []string{"unrelated"},
			Expected: "sha256",
		},
		{
			Name:     "Other",
			Args:     []string{"-algorithm", "sha512"},
			Expected: "sha512",
		},
	} {
		t.Run(testcase.Name, func(t *testing.T) {
			alg = Canonical
			if err := flagSet.Parse(testcase.Args); err != testcase.Err {
				if testcase.Err == nil {
					t.Fatal("unexpected error", err)
				}

				// check that flag package returns correct error
				if !strings.Contains(err.Error(), testcase.Err.Error()) {
					t.Fatalf("unexpected error: %v != %v", err, testcase.Err)
				}
				return
			}

			if alg != testcase.Expected {
				t.Fatalf("unexpected algorithm: %v != %v", alg, testcase.Expected)
			}
		})
	}
}

func TestFroms(t *testing.T) {
	p := make([]byte, 1<<20)
	rand.Read(p)

	for alg := range algorithms {
		h := alg.Hash()
		h.Write(p)
		expected := Digest(fmt.Sprintf("%s:%x", alg, h.Sum(nil)))
		readerDgst, err := alg.FromReader(bytes.NewReader(p))
		if err != nil {
			t.Fatalf("error calculating hash from reader: %v", err)
		}

		dgsts := []Digest{
			alg.FromBytes(p),
			alg.FromString(string(p)),
			readerDgst,
		}

		if alg == Canonical {
			readerDgst, err := FromReader(bytes.NewReader(p))
			if err != nil {
				t.Fatalf("error calculating hash from reader: %v", err)
			}

			dgsts = append(dgsts,
				FromBytes(p),
				FromString(string(p)),
				readerDgst)
		}
		for _, dgst := range dgsts {
			if dgst != expected {
				t.Fatalf("unexpected digest %v != %v", dgst, expected)
			}
		}
	}
}

func TestBadAlgorithmNameRegistration(t *testing.T) {
	expectPanic := func(algorithm string) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("Expected panic and did not find one")
			}
			t.Logf("Captured panic: %v", r)
		}()
		// We just use SHA256 here as a test / stand-in
		RegisterAlgorithm(Algorithm(algorithm), crypto.SHA256)
	}

	expectPanic("sha256-")
	expectPanic("-")
	expectPanic("SHA256")
	expectPanic("sha25*")
}

func TestGoodAlgorithmNameRegistration(t *testing.T) {
	expectNoPanic := func(algorithm string) {
		defer func() {
			r := recover()
			if r != nil {
				t.Fatalf("Expected panic and found one: %v", r)
			}
		}()

		// We just use SHA256 here as a test / stand-in
		RegisterAlgorithm(Algorithm(algorithm), crypto.SHA256)
	}

	expectNoPanic("sha256-test")
	expectNoPanic("sha256_384")
}
