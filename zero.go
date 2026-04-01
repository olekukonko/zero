package zero

import (
	"reflect"
	"runtime"
	"unsafe"
)

// Zero securely zeros out any value in Go.
// Works for: basic types, pointers, slices, arrays, structs, maps, strings, interfaces.
//
// For strings:
//   - Zero(&myString) sets the string variable to "" (clears the reference).
//   - The backing byte data is NOT zeroed here. This prevents fatal SIGBUS
//     on string literals (which live in read-only memory on darwin-arm64
//     and many other platforms).
//   - If you need to attempt zeroing the backing data of a string, use the
//     separate String() helper (it has its own panic recovery).
func Zero(v any) {
	if v == nil {
		return
	}

	val := reflect.ValueOf(v)

	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		zeroValue(val.Elem())
		runtime.KeepAlive(v)
		return
	}

	ptr := reflect.New(val.Type())
	ptr.Elem().Set(val)
	zeroValue(ptr.Elem())

	if val.CanAddr() {
		val.Set(ptr.Elem())
	}

	runtime.KeepAlive(v)
}

// zeroValue recursively zeros a reflect.Value.
func zeroValue(val reflect.Value) {
	if !val.IsValid() {
		return
	}

	switch val.Kind() {
	case reflect.Ptr:
		if val.IsNil() {
			return
		}
		zeroValue(val.Elem())
		if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	case reflect.Interface:
		if val.IsNil() {
			return
		}
		zeroValue(val.Elem())
		if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	case reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			zeroValue(val.Index(i))
		}
		zeroMemory(unsafe.Pointer(val.Pointer()), uintptr(val.Len())*val.Type().Elem().Size())
		if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	case reflect.Array:
		for i := 0; i < val.Len(); i++ {
			zeroValue(val.Index(i))
		}

	case reflect.Struct:
		for i := 0; i < val.NumField(); i++ {
			zeroValue(val.Field(i))
		}

	case reflect.Map:
		keys := val.MapKeys()
		for _, key := range keys {
			val.SetMapIndex(key, reflect.Value{})
		}
		zeroMemory(unsafe.Pointer(val.Pointer()), uintptr(unsafe.Sizeof(map[int]int{})))
		if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	case reflect.String:
		if val.CanSet() {
			val.SetString("")
		}

	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		if val.CanAddr() {
			zeroMemory(unsafe.Pointer(val.UnsafeAddr()), val.Type().Size())
		} else if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	case reflect.Chan, reflect.Func:
		if val.CanSet() {
			val.Set(reflect.Zero(val.Type()))
		}

	default:
		if val.CanAddr() {
			zeroMemory(unsafe.Pointer(val.UnsafeAddr()), val.Type().Size())
		}
	}
}

// zeroMemory securely zeroes a memory region using byte-by-byte writes.
func zeroMemory(ptr unsafe.Pointer, size uintptr) {
	if ptr == nil || size == 0 {
		return
	}
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Add(ptr, i)) = 0
	}
	runtime.Gosched()
}

// String securely zeros a string's backing data and clears the variable.
// First sets *s = "" to clear the reference, then attempts to zero the
// backing bytes. Panics from read-only memory are recovered silently.
// Pass a pointer to the string variable: String(&myString).
func String(s *string) {
	if s == nil || *s == "" {
		return
	}

	data := unsafe.StringData(*s)
	size := uintptr(len(*s))

	*s = ""

	if data != nil && size > 0 {
		func() {
			defer func() { recover() }()
			zeroMemory(unsafe.Pointer(data), size)
		}()
	}
}

// Byte zeros a byte slice's backing array in place.
// The slice header remains valid but all bytes are set to 0.
func Byte(buf []byte) {
	if len(buf) == 0 {
		return
	}
	zeroMemory(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
}
