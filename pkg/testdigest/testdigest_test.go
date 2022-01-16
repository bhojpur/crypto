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

import (
	"testing"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/bhojpur/crypto/pkg/digest"
)

func TestParseDigest(t *testing.T) {
	RunTestCases(t, []TestCase{
		{
			Input:     "sha256:e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b",
			Algorithm: "sha256",
			Encoded:   "e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b",
		},
		{
			Input:     "sha384:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
		},
		{
			// empty
			Input: "",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// whitespace only
			Input: "     ",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// empty hex
			Input: "sha256:",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// hex with correct length, but whitespace only
			Input: "sha256:                                                                ",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// empty hex
			Input: ":",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// just hex
			Input: "d41d8cd98f00b204e9800998ecf8427e",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// not hex
			Input: "sha256:d41d8cd98f00b204e9800m98ecf8427e",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			// too short
			Input: "sha256:abcdef0123456789",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			// too short (from different Algorithm)
			Input: "sha512:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			Input: "foo:d41d8cd98f00b204e9800998ecf8427e",
			Err:   digest.ErrDigestUnsupported,
		},
		{
			// repeated separators
			Input: "sha384__foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// ensure that we parse, but we don't have support for the Algorithm
			Input:     "sha384.foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384.foo+bar",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input:     "sha384_foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384_foo+bar",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input:     "sha256+b64:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
			Algorithm: "sha256+b64",
			Encoded:   "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input: "sha256:E58FCF7418D4390DEC8E8FB69D88C06EC07039D651FEDD3AA72AF9972E7D046B",
			Err:   digest.ErrDigestInvalidFormat,
		},
	})
}
