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
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

// Digest allows simple protection of hex formatted digest strings, prefixed
// by their algorithm. Strings of type Digest have some guarantee of being in
// the correct format and it provides quick access to the components of a
// digest string.
//
// The following is an example of the contents of Digest types:
//
// 	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
//
// This allows to abstract the digest behind this type and work only in those
// terms.
type Digest string

// NewDigest returns a Digest from alg and a hash.Hash object.
func NewDigest(alg Algorithm, h hash.Hash) Digest {
	return NewDigestFromBytes(alg, h.Sum(nil))
}

// NewDigestFromBytes returns a new digest from the byte contents of p.
// Typically, this can come from hash.Hash.Sum(...) or xxx.SumXXX(...)
// functions. This is also useful for rebuilding digests from binary
// serializations.
func NewDigestFromBytes(alg Algorithm, p []byte) Digest {
	return NewDigestFromEncoded(alg, alg.Encode(p))
}

// NewDigestFromHex is deprecated. Please use NewDigestFromEncoded.
func NewDigestFromHex(alg, hex string) Digest {
	return NewDigestFromEncoded(Algorithm(alg), hex)
}

// NewDigestFromEncoded returns a Digest from alg and the encoded digest.
func NewDigestFromEncoded(alg Algorithm, encoded string) Digest {
	return Digest(fmt.Sprintf("%s:%s", alg, encoded))
}

// DigestRegexp matches valid digest types.
var DigestRegexp = regexp.MustCompile(`[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`)

// DigestRegexpAnchored matches valid digest types, anchored to the start and end of the match.
var DigestRegexpAnchored = regexp.MustCompile(`^` + DigestRegexp.String() + `$`)

var (
	// ErrDigestInvalidFormat returned when digest format invalid.
	ErrDigestInvalidFormat = fmt.Errorf("invalid checksum digest format")

	// ErrDigestInvalidLength returned when digest has invalid length.
	ErrDigestInvalidLength = fmt.Errorf("invalid checksum digest length")

	// ErrDigestUnsupported returned when the digest algorithm is unsupported.
	ErrDigestUnsupported = fmt.Errorf("unsupported digest algorithm")
)

// Parse parses s and returns the validated digest object. An error will
// be returned if the format is invalid.
func Parse(s string) (Digest, error) {
	d := Digest(s)
	return d, d.Validate()
}

// FromReader consumes the content of rd until io.EOF, returning canonical digest.
func FromReader(rd io.Reader) (Digest, error) {
	return Canonical.FromReader(rd)
}

// FromBytes digests the input and returns a Digest.
func FromBytes(p []byte) Digest {
	return Canonical.FromBytes(p)
}

// FromString digests the input and returns a Digest.
func FromString(s string) Digest {
	return Canonical.FromString(s)
}

// Validate checks that the contents of d is a valid digest, returning an
// error if not.
func (d Digest) Validate() error {
	s := string(d)
	i := strings.Index(s, ":")
	if i <= 0 || i+1 == len(s) {
		return ErrDigestInvalidFormat
	}
	algorithm, encoded := Algorithm(s[:i]), s[i+1:]
	if !algorithm.Available() {
		if !DigestRegexpAnchored.MatchString(s) {
			return ErrDigestInvalidFormat
		}
		return ErrDigestUnsupported
	}
	return algorithm.Validate(encoded)
}

// Algorithm returns the algorithm portion of the digest. This will panic if
// the underlying digest is not in a valid format.
func (d Digest) Algorithm() Algorithm {
	return Algorithm(d[:d.sepIndex()])
}

// Verifier returns a writer object that can be used to verify a stream of
// content against the digest. If the digest is invalid, the method will panic.
func (d Digest) Verifier() Verifier {
	return hashVerifier{
		hash:   d.Algorithm().Hash(),
		digest: d,
	}
}

// Encoded returns the encoded portion of the digest. This will panic if the
// underlying digest is not in a valid format.
func (d Digest) Encoded() string {
	return string(d[d.sepIndex()+1:])
}

// Hex is deprecated. Please use Digest.Encoded.
func (d Digest) Hex() string {
	return d.Encoded()
}

func (d Digest) String() string {
	return string(d)
}

func (d Digest) sepIndex() int {
	i := strings.Index(string(d), ":")

	if i < 0 {
		panic(fmt.Sprintf("no ':' separator in digest %q", d))
	}

	return i
}
