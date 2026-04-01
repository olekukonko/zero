package zero

import (
	"bytes"
	"testing"
)

type Secret struct {
	ID       int
	Password string
	Token    []byte
	APIKey   [32]byte
}

type Nested struct {
	A *int
	B []string
	C map[string]interface{}
}

func TestZero_BasicTypes(t *testing.T) {
	num := 42
	Zero(&num)
	if num != 0 {
		t.Errorf("expected 0, got %d", num)
	}

	str := "secret"
	Zero(&str)
	if str != "" {
		t.Errorf("expected empty string, got %q", str)
	}

	f := 3.14
	Zero(&f)
	if f != 0 {
		t.Errorf("expected 0, got %f", f)
	}

	b := true
	Zero(&b)
	if b != false {
		t.Errorf("expected false, got %v", b)
	}
}

func TestZero_Slice(t *testing.T) {
	data := []int{1, 2, 3, 4, 5}
	Zero(&data)
	for i, v := range data {
		if v != 0 {
			t.Errorf("expected 0 at index %d, got %d", i, v)
		}
	}
}

func TestZero_Array(t *testing.T) {
	arr := [10]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	Zero(&arr)
	for i, v := range arr {
		if v != 0 {
			t.Errorf("expected 0 at index %d, got %d", i, v)
		}
	}
}

func TestZero_Struct(t *testing.T) {
	secret := Secret{
		ID:       123,
		Password: "super-secret",
		Token:    []byte("auth-token-123"),
		APIKey:   [32]byte{1, 2, 3, 4, 5},
	}

	Zero(&secret)

	if secret.ID != 0 {
		t.Errorf("expected ID=0, got %d", secret.ID)
	}
	if secret.Password != "" {
		t.Errorf("expected empty Password, got %q", secret.Password)
	}
	if len(secret.Token) > 0 && !bytes.Equal(secret.Token, make([]byte, len(secret.Token))) {
		t.Errorf("expected zeroed Token")
	}
	for i, v := range secret.APIKey {
		if v != 0 {
			t.Errorf("expected 0 at APIKey[%d], got %d", i, v)
		}
	}
}

func TestZero_Map(t *testing.T) {
	userMap := map[string]string{
		"password": "secret123",
		"token":    "xyz789",
	}
	Zero(&userMap)
	if len(userMap) != 0 {
		t.Errorf("expected empty map, got %d entries", len(userMap))
	}
}

func TestZero_Nested(t *testing.T) {
	a := 42
	nested := Nested{
		A: &a,
		B: []string{"secret1", "secret2"},
		C: map[string]interface{}{
			"key": "value",
		},
	}

	Zero(&nested)

	if nested.A != nil && *nested.A != 0 {
		t.Errorf("expected A=0 or nil, got %v", nested.A)
	}
	if len(nested.B) != 0 {
		t.Errorf("expected empty B slice, got %v", nested.B)
	}
	if len(nested.C) != 0 {
		t.Errorf("expected empty C map, got %v", nested.C)
	}
}

func TestZero_Nil(t *testing.T) {
	Zero(nil)
	var p *int
	Zero(p)
}

func TestZero_NonPointer(t *testing.T) {
	num := 42
	Zero(num)
	if num != 42 {
		t.Error("non-pointer should not be modified")
	}
}

func TestZero_Pointer(t *testing.T) {
	a := 42
	p := &a
	Zero(&p)
	if p != nil {
		t.Error("expected nil pointer")
	}
}

func TestSecureZeroString(t *testing.T) {
	// Use a mutable string built from bytes to ensure writable backing memory.
	original := []byte("secret")
	s := string(original)

	if s != "secret" {
		t.Fatalf("setup failed: expected 'secret', got %q", s)
	}

	String(&s)

	if s != "" {
		t.Errorf("expected empty string after zeroing, got %q", s)
	}

	// Note: Go copies byte slice when converting to string, so original
	// slice is not modified. We verify the string variable is cleared.
}

func TestZero_ComplexTypes(t *testing.T) {
	c := complex(1, 2)
	Zero(&c)
	if c != 0 {
		t.Errorf("expected 0, got %v", c)
	}

	ch := make(chan int, 1)
	Zero(&ch)
	if ch != nil {
		t.Error("expected nil channel")
	}
}

func TestZero_Interface(t *testing.T) {
	// Create an addressable interface value via a struct field.
	type Container struct {
		V interface{}
	}
	c := Container{V: 42}
	Zero(&c.V)
	if c.V != nil && c.V != 0 {
		t.Errorf("expected nil or zero, got %v", c.V)
	}
}

func BenchmarkZero_Struct(b *testing.B) {
	secret := Secret{
		ID:       123,
		Password: "super-secret",
		Token:    []byte("auth-token-123"),
		APIKey:   [32]byte{1, 2, 3, 4, 5},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := secret
		Zero(&s)
	}
}

func BenchmarkZero_Slice(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := make([]byte, 1024)
		copy(s, data)
		Zero(&s)
	}
}
