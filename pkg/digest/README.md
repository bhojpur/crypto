# Bhojpur Crypto - Digest
It is a collection of common digest packages used across the Bhojpur.NET Platform ecosystem.

# What is a digest?

A digest is just a [hash](https://en.wikipedia.org/wiki/Hash_function).

The most common use case for a digest is to create a content identifier for use in [Content Addressable Storage](https://en.wikipedia.org/wiki/Content-addressable_storage) systems:

```go
id := digest.FromBytes([]byte("my content"))
```

In the example above, the id can be used to uniquely identify the byte slice "my content".
This allows two disparate applications to agree on a verifiable identifier without having to trust one another.

An identifying digest can be verified, as follows:

```go
if id != digest.FromBytes([]byte("my content")) {
  return errors.New("the content has changed!")
}
```

A `Verifier` type can be used to handle cases where an `io.Reader` makes more sense:

```go
rd := getContent()
verifier := id.Verifier()
io.Copy(verifier, rd)

if !verifier.Verified() {
  return errors.New("the content has changed!")
}
```

Using [Merkle DAGs](https://en.wikipedia.org/wiki/Merkle_tree), this can power a rich, safe, content distribution system.

# Usage

1. Make sure to import the hash implementations into your application or the package will panic.
    You should have something like the following in the main (or other entrypoint) of your application:
   
    ```go
    import (
        _ "crypto/sha256"
        _ "crypto/sha512"
    )
    ```
    This may seem inconvenient but it allows you replace the hash
    implementations with others, such as https://github.com/bhojpur/crypto/pkg/resumable.
 
2. Even though `digest.Digest` may be assemblable as a string, _always_ verify your input with `digest.Parse` or use `Digest.Validate` when accepting untrusted input.
    While there are measures to avoid common problems, this will ensure you have valid digests in the rest of your application.

3. While alternative encodings of hash values (digests) are possible (for example, base64), this package deals exclusively with hex-encoded digests.