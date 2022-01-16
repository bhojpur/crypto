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

// Package digest provides a generalized type to opaquely represent message
// digests and their operations within the Bhojpur Registry. The Digest type is
// designed to serve as a flexible identifier in a content-addressable system.
// More importantly, it provides tools and wrappers to work with
// hash.Hash-based digests with little effort.
//
// Basics
//
// The format of a digest is simply a string with two parts, dubbed the
// "algorithm" and the "digest", separated by a colon:
//
// 	<algorithm>:<digest>
//
// An example of a sha256 digest representation follows:
//
// 	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
//
// The "algorithm" portion defines both the hashing algorithm used to calculate
// the digest and the encoding of the resulting digest, which defaults to "hex"
// if not otherwise specified. Currently, all supported algorithms have their
// digests encoded in hex strings.
//
// In the example above, the string "sha256" is the algorithm and the hex bytes
// are the "digest".
//
// Because the Digest type is simply a string, once a valid Digest is
// obtained, comparisons are cheap, quick and simple to express with the
// standard equality operator.
//
// Verification
//
// The main benefit of using the Digest type is simple verification against a
// given digest. The Verifier interface, modeled after the stdlib hash.Hash
// interface, provides a common write sink for digest verification. After
// writing is complete, calling the Verifier.Verified method will indicate
// whether or not the stream of bytes matches the target digest.
//
// Missing Features
//
// In addition to the above, we intend to add the following features to this
// package:
//
// 1. A Digester type that supports write sink digest calculation.
//
// 2. Suspend and resume of ongoing digest calculations to support efficient digest verification in the registry.
//
package digest
