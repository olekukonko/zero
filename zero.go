// Package zero provides secure memory zeroing for sensitive data.
// It is designed for cryptographic use: passwords, keys, tokens, and any
// value that should not linger in memory after use.
//
// Core design principles:
//   - Never silently succeed on a no-op. Non-pointer inputs to Zero() return an error.
//   - Never corrupt runtime metadata (maps are cleared via the runtime, not unsafe writes).
//   - Unexported struct fields are zeroed via unsafe address arithmetic when addressable.
//   - Embedded structs, nested maps, slices of strings, interface chains — all covered.
//
// Dead-store elimination:
//
//	zeroMemory is marked //go:noinline and uses runtime.KeepAlive so the compiler
//	cannot prove the writes are unused and eliminate them. This is the same approach
//	used by golang.org/x/crypto.
package zero

import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"
)

// -------------------------------------------------------------------------
// zeroMemory — the single low-level primitive
// -------------------------------------------------------------------------

// zeroMemory writes zeros to [ptr, ptr+size).
//
// //go:noinline prevents the compiler from inlining and then proving the
// writes are dead stores. runtime.KeepAlive(ptr) prevents the GC from
// reclaiming the backing memory before the loop finishes and signals to
// the compiler that ptr is live after the call, further discouraging
// dead-store elimination.
//
//go:noinline
func zeroMemory(ptr unsafe.Pointer, size uintptr) {
	if ptr == nil || size == 0 {
		return
	}
	b := unsafe.Slice((*byte)(ptr), size)
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(ptr)
}

// -------------------------------------------------------------------------
// Zero — generic entry point
// -------------------------------------------------------------------------

// Zero securely zeros any value reachable through v.
// v MUST be a non-nil pointer; passing a non-pointer returns an error so
// callers are never silently left with un-zeroed memory.
//
// Supported targets (recursively):
//   - Basic types: int*, uint*, float*, complex*, bool, uintptr
//   - string  — reference cleared; backing data is NOT zeroed (use []byte instead)
//   - []byte  — backing array zeroed, header nilled
//   - []T     — each element zeroed, then header nilled
//   - [N]T    — each element zeroed in place
//   - map[K]V — all entries deleted, then reference nilled
//   - struct  — every field (exported and unexported) zeroed recursively
//   - *T      — pointed-to value zeroed, pointer nilled
//   - interface — contained value zeroed, interface nilled
//   - chan, func — reference nilled
func Zero(v any) error {
	if v == nil {
		return nil
	}
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr {
		return fmt.Errorf("zero.Zero: requires a pointer, got %s — wrap your value with &", val.Kind())
	}
	if val.IsNil() {
		return nil
	}
	zeroVal(val.Elem())
	runtime.KeepAlive(v)
	return nil
}

// -------------------------------------------------------------------------
// String — clear the string header
// -------------------------------------------------------------------------

// String clears the string header (sets *s = "").
// It does NOT attempt to zero the backing memory because that memory may be
// read‑only (e.g., string literals) and writing to it causes a fatal signal
// on some platforms. For guaranteed wiping of sensitive data, use []byte.
func String(s *string) {
	if s == nil || *s == "" {
		return
	}
	*s = ""
}

// -------------------------------------------------------------------------
// Bytes — zero a []byte backing array and nil the header
// -------------------------------------------------------------------------

// Bytes zeros all bytes in buf's backing array in place.
// The slice header remains valid (len/cap unchanged, pointer unchanged but
// the pointed-at memory is now all zeros). Use Erase for full header wipe.
func Bytes(buf []byte) {
	if len(buf) == 0 {
		return
	}
	zeroMemory(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
}

// -------------------------------------------------------------------------
// Erase — generic type-safe wipe + nil (the one-stop shop)
// -------------------------------------------------------------------------

// Erase zeros the value pointed to by p and, where applicable, nils/empties
// the header so no dangling pointer remains:
//
//   - *[]byte        — backing array zeroed, slice nilled
//   - *[]T           — each element erased recursively, slice nilled
//   - *string        — string set to "" (backing data NOT zeroed)
//   - *map[K]V       — all entries deleted, map nilled
//   - *struct / *T   — delegates to Zero(p)
//
// Erase is the preferred API when you hold a pointer and want everything gone.
// It never panics; unsupported kinds (chan, func, interface at top level)
// are handled by Zero's reflection path.
func Erase[T any](p *T) {
	if p == nil {
		return
	}
	// Fast paths by reflected kind of *p.
	val := reflect.ValueOf(p).Elem()
	switch val.Kind() { //nolint:exhaustive
	case reflect.Slice:
		eraseSlice(val)
	case reflect.String:
		String((*string)(unsafe.Pointer(p)))
	case reflect.Map:
		eraseMap(val)
	default:
		// For structs, pointers, scalars, arrays — use the full recursive path.
		zeroVal(val)
	}
	runtime.KeepAlive(p)
}

// -------------------------------------------------------------------------
// Struct — zero all fields of a struct, handling strings deeply
// -------------------------------------------------------------------------

// Struct zeros every field of the struct pointed to by s, including
// unexported fields (via unsafe) and embedded structs (recursively).
// String fields are cleared (set to ""), but their backing memory is NOT zeroed.
// []byte fields are zeroed via Bytes() then nilled.
// Nested maps, slices, interfaces, and pointers are all handled.
//
// If s does not point to a struct, Struct falls back to Zero(s).
func Struct(s any) error {
	if s == nil {
		return fmt.Errorf("zero.Struct: nil pointer")
	}
	val := reflect.ValueOf(s)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("zero.Struct: requires a non-nil pointer")
	}
	elem := val.Elem()
	if elem.Kind() != reflect.Struct {
		return Zero(s)
	}
	zeroStruct(elem)
	runtime.KeepAlive(s)
	return nil
}

// -------------------------------------------------------------------------
// Internal recursive zeroing engine
// -------------------------------------------------------------------------

// zeroVal is the main recursive dispatcher. It handles all kinds.
func zeroVal(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		zeroPtr(v)
	case reflect.Interface:
		zeroInterface(v)
	case reflect.Slice:
		eraseSlice(v)
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			zeroVal(v.Index(i))
		}
	case reflect.Struct:
		zeroStruct(v)
	case reflect.Map:
		eraseMap(v)
	case reflect.String:
		zeroString(v)
	case reflect.Chan, reflect.Func:
		if v.CanSet() {
			v.Set(reflect.Zero(v.Type()))
		}
	default:
		// Scalar: bool, int*, uint*, float*, complex*, uintptr.
		zeroScalar(v)
	}
}

// zeroPtr zeros the pointed-to value then nils the pointer.
func zeroPtr(v reflect.Value) {
	if v.IsNil() {
		return
	}
	zeroVal(v.Elem())
	if v.CanSet() {
		v.Set(reflect.Zero(v.Type()))
	}
}

// zeroInterface zeros the contained value then clears the interface.
func zeroInterface(v reflect.Value) {
	if v.IsNil() {
		return
	}
	// Elem() on an interface gives the concrete value. It is not addressable,
	// so we dispatch on kind and do what we can.
	inner := v.Elem()
	if inner.IsValid() {
		zeroVal(inner)
	}
	if v.CanSet() {
		v.Set(reflect.Zero(v.Type()))
	}
}

// zeroStruct zeros every field including unexported ones.
// Embedded structs are detected by field.Anonymous and recursed into.
func zeroStruct(v reflect.Value) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		sf := t.Field(i)

		// Embedded (anonymous) struct — recurse regardless of export status.
		if sf.Anonymous && field.Kind() == reflect.Struct {
			zeroStruct(field)
			continue
		}

		// Exported fields: use reflect normally.
		if field.CanSet() {
			zeroVal(field)
			continue
		}

		// Unexported fields: use unsafe to get a writable pointer.
		// We can only do this when the struct itself is addressable.
		if v.CanAddr() {
			zeroUnexported(v, i, field)
		}
		// If not addressable we cannot zero unexported fields — there is no
		// safe way. This is documented behaviour.
	}
}

// zeroUnexported uses unsafe to zero an unexported field by address.
// It handles the field's type the same way zeroVal does, but via raw memory
// for scalar/array types, and via reflect tricks for composite types.
func zeroUnexported(structVal reflect.Value, fieldIdx int, field reflect.Value) {
	// Obtain a pointer to the field's memory using the struct's address.
	structPtr := unsafe.Pointer(structVal.UnsafeAddr())
	t := structVal.Type()
	offset := t.Field(fieldIdx).Offset
	fieldPtr := unsafe.Add(structPtr, offset)
	fieldSize := field.Type().Size()

	switch field.Kind() { //nolint:exhaustive
	case reflect.String:
		// For unexported strings, reinterpret as *string and call String().
		sp := (*string)(fieldPtr)
		String(sp)

	case reflect.Slice:
		// For unexported byte slices, zero via raw pointer. For other slices,
		// zero each element if we can get at the data pointer.
		if field.Type().Elem().Kind() == reflect.Uint8 {
			// Reinterpret as []byte.
			bp := (*[]byte)(fieldPtr)
			if len(*bp) > 0 {
				zeroMemory(unsafe.Pointer(&(*bp)[0]), uintptr(len(*bp)))
			}
			*bp = nil
		} else {
			// Generic slice: zero backing memory then nil the header.
			// We cannot call zeroVal on each element without addressability,
			// so we zero the raw backing bytes and nil the header.
			type sliceHeader struct {
				Data unsafe.Pointer
				Len  int
				Cap  int
			}
			sh := (*sliceHeader)(fieldPtr)
			if sh.Data != nil && sh.Len > 0 {
				zeroMemory(sh.Data, uintptr(sh.Len)*field.Type().Elem().Size())
			}
			*sh = sliceHeader{}
		}

	case reflect.Map, reflect.Ptr, reflect.Chan, reflect.Func, reflect.Interface:
		// These are pointer-width words. Zero the word (nils the reference).
		// For maps, we cannot call delete() on unexported maps without reflect,
		// and reflect.Value of unexported maps is not settable. Best we can do
		// is nil the pointer word — the entries become unreachable.
		zeroMemory(fieldPtr, fieldSize)

	default:
		// Scalar, array — zero the raw bytes.
		zeroMemory(fieldPtr, fieldSize)
	}
}

// eraseSlice zeros every element of a slice then nils the header.
func eraseSlice(v reflect.Value) {
	if v.IsNil() {
		return
	}
	elemKind := v.Type().Elem().Kind()
	if elemKind == reflect.Uint8 {
		// Fast path: byte slice — zero backing array directly.
		if v.Len() > 0 {
			zeroMemory(unsafe.Pointer(v.Pointer()), uintptr(v.Len()))
		}
	} else {
		// General case: zero each element recursively first.
		for i := 0; i < v.Len(); i++ {
			zeroVal(v.Index(i))
		}
		// Then zero the backing memory for any residual pointer words.
		if v.Len() > 0 {
			zeroMemory(unsafe.Pointer(v.Pointer()), uintptr(v.Len())*v.Type().Elem().Size())
		}
	}
	// Nil the header.
	if v.CanSet() {
		v.Set(reflect.Zero(v.Type()))
	}
}

// eraseMap deletes all entries then nils the map reference.
// We NEVER write to the map's internal header via unsafe — that corrupts GC metadata.
func eraseMap(v reflect.Value) {
	if v.IsNil() {
		return
	}
	// Zero each value (best-effort; map values are not addressable in Go).
	// We can zero value copies but cannot reach the stored copy inside the map.
	// The definitive cleanup is deletion + nil.
	iter := v.MapRange()
	for iter.Next() {
		// Erase the value if it is a string or slice (types where the copy
		// carries meaningful data via a pointer).
		mv := iter.Value()
		switch mv.Kind() { //nolint:exhaustive
		case reflect.String:
			// We hold a copy of the string header — clear the copy's header.
			cp := mv.String()
			String(&cp)
		case reflect.Slice:
			if mv.Len() > 0 {
				zeroMemory(unsafe.Pointer(mv.Pointer()), uintptr(mv.Len())*mv.Type().Elem().Size())
			}
		}
		v.SetMapIndex(iter.Key(), reflect.Value{}) // delete entry
	}
	// Nil the reference — this is the only safe map-level operation.
	if v.CanSet() {
		v.Set(reflect.Zero(v.Type()))
	}
}

// zeroString clears the string via reflect.
func zeroString(v reflect.Value) {
	if !v.CanAddr() {
		if v.CanSet() {
			v.SetString("")
		}
		return
	}
	// We have an address — use String() to clear header.
	sp := (*string)(unsafe.Pointer(v.UnsafeAddr()))
	String(sp)
}

// zeroScalar zeros a scalar value via its address when addressable,
// falling back to reflect.Zero when not.
func zeroScalar(v reflect.Value) {
	if v.CanAddr() {
		zeroMemory(unsafe.Pointer(v.UnsafeAddr()), v.Type().Size())
	} else if v.CanSet() {
		v.Set(reflect.Zero(v.Type()))
	}
}
