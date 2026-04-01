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
	// Zero any value
	password := "super-secret"
	zero.Zero(&password) // password is now ""

	// Zero struct fields
	type Token struct {
		Key  string
		Data []byte
	}
	t := Token{Key: "abc123", Data: []byte("sensitive")}
	zero.Zero(&t) // all fields zeroed

	// Zero slice elements and backing array
	buf := []byte("secret data")
	zero.Bytes(buf) // all bytes set to 0, slice is nil

	// String helper also zeros backing bytes (with panic recovery for read-only literals)
	s := "mutable"
	zero.String(&s) // s is "", backing bytes zeroed
}
```

## How It Works

- `Zero(v any)` - Recursively zeros values via reflection and unsafe memory writes
- `Bytes([]byte)` - takes value, modifies backing memory (mutable data)
- `String(s *string)` - Clears string reference and attempts to zero backing bytes (recovers from SIGBUS on string literals in read-only memory)

## Safety

- Handles nil pointers gracefully
- Recovers from panics when zeroing string literals (read-only memory on Darwin ARM64)
- Uses `runtime.KeepAlive` to prevent GC from collecting values mid-zeroing

## License

MIT