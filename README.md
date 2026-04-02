# zero

Secure memory zeroing for Go. Wipes sensitive data from memory to prevent leaks in dumps, core files, and swap.

## Install

```bash
go get github.com/olekukonko/zero
```

## Usage

```go
package main

import "github.com/olekukonko/zero"

func main() {
    // Zero any value (strings are cleared, but backing memory is NOT zeroed)
    password := "super-secret"
    zero.Zero(&password) // password is now ""

    // For guaranteed wiping of string data, use []byte instead
    secret := []byte("super-secret")
    zero.Bytes(secret) // all bytes set to 0, but header remains
    zero.Erase(&secret) // header also nilled

    // Zero struct fields recursively
    type Token struct {
        Key  string
        Data []byte
    }
    t := Token{Key: "abc123", Data: []byte("sensitive")}
    zero.Zero(&t) // t.Key = "", t.Data = nil (backing bytes zeroed)

    // Bytes zeros the backing array of a byte slice
    buf := []byte("secret data")
    zero.Bytes(buf) // all bytes become 0, but buf still has len/cap

    // Erase is the one‑stop shop: zeros backing memory and nils the header
    zero.Erase(&buf) // buf == nil

    // String clears the string header (does NOT zero backing memory)
    s := "hello"
    zero.String(&s) // s == ""
}
```

## Important Notes on Strings

- **`string` values in Go may be backed by read‑only memory** (e.g., string literals). Writing to that memory causes a fatal signal on platforms like macOS ARM64.
- For this reason, **`zero.String` and `zero.Zero` on a `*string` only clear the string header** (`*s = ""`). They **do not** attempt to zero the underlying bytes.
- To securely wipe textual secrets, **use `[]byte`** instead of `string`. You can convert a string to a mutable byte slice with `[]byte("...")` when you control the source.

## How It Works

- `Zero(v any)` – Recursively zeros values via reflection and unsafe memory writes.
- `Bytes([]byte)` – Overwrites the backing array of a byte slice in place (mutable data).
- `String(s *string)` – Clears the string reference (header only).
- `Erase[T any](p *T)` – Type‑safe wrapper that zeros the target and nils the header.
- `Struct(s any)` – Like `Zero`, but only works on structs and returns an error for nil.

The package uses `//go:noinline` and `runtime.KeepAlive` to prevent the compiler from eliminating zeroing writes as dead stores.

## Safety

- Handles nil pointers gracefully.
- Never writes to map headers (uses `delete` + `nil`).
- Zeroes unexported struct fields via unsafe when the struct is addressable.
- Does **not** attempt to write to read‑only string memory (avoids SIGBUS crashes).

## License

MIT