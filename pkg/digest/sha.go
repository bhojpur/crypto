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
	"crypto"

	// make sure crypto.SHA256 is registered
	_ "crypto/sha256"

	// make sure crypto.sha512 and crypto.SHA384 are registered
	_ "crypto/sha512"
)

const (
	SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
	SHA384 Algorithm = "sha384" // sha384 with hex encoding (lower case only)
	SHA512 Algorithm = "sha512" // sha512 with hex encoding (lower case only)
)

func init() {
	RegisterAlgorithm(SHA256, crypto.SHA256)
	RegisterAlgorithm(SHA384, crypto.SHA384)
	RegisterAlgorithm(SHA512, crypto.SHA512)
}
