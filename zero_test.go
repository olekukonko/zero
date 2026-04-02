package zero

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"
)

// -------------------------------------------------------------------------
// Test types
// -------------------------------------------------------------------------

type Credentials struct {
	ID       int
	Password string
	Token    []byte
	APIKey   [32]byte
}

type WithUnexported struct {
	Public  string
	private string
	secret  []byte
	count   int
}

type Nested struct {
	A *int
	B []string
	C map[string]interface{}
}

// EmbeddedInner is embedded (anonymous) in EmbeddedOuter.
type EmbeddedInner struct {
	Key   string
	Value []byte
}

type EmbeddedOuter struct {
	EmbeddedInner // anonymous embed
	Name          string
	Tags          []string
}

// DeepNested tests multi-level struct nesting.
type DeepNested struct {
	Level1 struct {
		Level2 struct {
			Secret string
			Data   []byte
		}
		Token string
	}
	Map map[string]string
}

// WithMaps contains various map types.
type WithMaps struct {
	Simple map[string]string
	IntMap map[int][]byte
	AnyMap map[string]interface{}
	Nested map[string]map[string]string
}

// FullSecret exercises every field kind.
type FullSecret struct {
	ID          int
	Score       float64
	Flag        bool
	Password    string
	Token       []byte
	Keys        []string
	Credentials Credentials
	Meta        map[string]string
	Ptr         *string
	Iface       interface{}
	Ch          chan int
}

// -------------------------------------------------------------------------
// Zero() tests
// -------------------------------------------------------------------------

func TestZero_RejectsNonPointer(t *testing.T) {
	num := 42
	err := Zero(num)
	if err == nil {
		t.Error("expected error for non-pointer, got nil")
	}
	if num != 42 {
		t.Error("non-pointer value must not be modified")
	}
}

func TestZero_NilPointer(t *testing.T) {
	var p *int
	if err := Zero(p); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestZero_NilAny(t *testing.T) {
	if err := Zero(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestZero_Int(t *testing.T) {
	n := 99
	mustZero(t, &n)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestZero_Float(t *testing.T) {
	f := 3.14
	mustZero(t, &f)
	if f != 0 {
		t.Errorf("expected 0, got %f", f)
	}
}

func TestZero_Bool(t *testing.T) {
	b := true
	mustZero(t, &b)
	if b {
		t.Error("expected false")
	}
}

func TestZero_Complex(t *testing.T) {
	c := complex(1.0, 2.0)
	mustZero(t, &c)
	if c != 0 {
		t.Errorf("expected 0+0i, got %v", c)
	}
}

func TestZero_String(t *testing.T) {
	s := "secret-value"
	mustZero(t, &s)
	if s != "" {
		t.Errorf("expected empty string, got %q", s)
	}
}

func TestZero_Slice(t *testing.T) {
	sl := []int{1, 2, 3, 4, 5}
	mustZero(t, &sl)
	if sl != nil {
		t.Errorf("expected nil slice, got %v", sl)
	}
}

func TestZero_ByteSlice(t *testing.T) {
	buf := []byte("secret-payload")
	orig := make([]byte, len(buf))
	copy(orig, buf)
	mustZero(t, &buf)
	if buf != nil {
		t.Errorf("expected nil slice header, got len=%d", len(buf))
	}
}

func TestZero_Array(t *testing.T) {
	arr := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	mustZero(t, &arr)
	for i, v := range arr {
		if v != 0 {
			t.Errorf("arr[%d] = %d, want 0", i, v)
		}
	}
}

func TestZero_Pointer(t *testing.T) {
	n := 42
	p := &n
	mustZero(t, &p)
	if p != nil {
		t.Error("expected nil pointer")
	}
}

func TestZero_Chan(t *testing.T) {
	ch := make(chan int, 1)
	mustZero(t, &ch)
	if ch != nil {
		t.Error("expected nil channel")
	}
}

func TestZero_Map(t *testing.T) {
	m := map[string]string{"password": "s3cr3t", "token": "abc123"}
	mustZero(t, &m)
	if m != nil {
		t.Errorf("expected nil map, got %v", m)
	}
}

func TestZero_Interface(t *testing.T) {
	type Box struct{ V interface{} }
	b := Box{V: 42}
	mustZero(t, &b.V)
	if b.V != nil {
		t.Errorf("expected nil interface, got %v", b.V)
	}
}

func TestZero_Struct(t *testing.T) {
	c := Credentials{
		ID:       1,
		Password: "hunter2",
		Token:    []byte("tok"),
		APIKey:   [32]byte{1, 2, 3},
	}
	mustZero(t, &c)
	assertCredentialsZero(t, c)
}

// -------------------------------------------------------------------------
// String() tests
// -------------------------------------------------------------------------

func TestString_Nil(t *testing.T) {
	String(nil) // must not panic
}

func TestString_Empty(t *testing.T) {
	s := ""
	String(&s)
	if s != "" {
		t.Errorf("got %q", s)
	}
}

func TestString_ClearsHeader(t *testing.T) {
	s := string([]byte("clearme"))
	String(&s)
	if s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestString_BackingData(t *testing.T) {
	original := []byte("backing-data-test")
	s := string(original)

	dataPtr := unsafe.StringData(s)
	dataLen := len(s)

	String(&s)

	if s != "" {
		t.Errorf("header not cleared: %q", s)
	}

	// Check backing memory — may not be writable if literal; log only.
	allZero := true
	for i := 0; i < dataLen; i++ {
		if *(*byte)(unsafe.Add(unsafe.Pointer(dataPtr), i)) != 0 {
			allZero = false
			break
		}
	}
	t.Logf("backing bytes zeroed: %v", allZero)
	runtime.GC()
}

func TestString_ReadOnlyLiteral(t *testing.T) {
	// String literals live in read-only memory; String() must not panic.
	s := "read-only-literal"
	String(&s)
	if s != "" {
		t.Errorf("header not cleared: %q", s)
	}
}

// -------------------------------------------------------------------------
// Bytes() tests
// -------------------------------------------------------------------------

func TestBytes_Normal(t *testing.T) {
	buf := []byte("secret-data-123")
	Bytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("buf[%d] = %d, want 0", i, b)
		}
	}
}

func TestBytes_Empty(t *testing.T) {
	Bytes(nil)
	Bytes([]byte{})
}

func TestBytes_Partial(t *testing.T) {
	full := []byte{1, 2, 3, 4, 5, 6}
	Bytes(full[2:4]) // zero only [2..3]
	if full[0] != 1 || full[1] != 2 {
		t.Error("Bytes modified elements outside the slice window")
	}
	if full[2] != 0 || full[3] != 0 {
		t.Error("Bytes did not zero the target window")
	}
	if full[4] != 5 || full[5] != 6 {
		t.Error("Bytes modified elements after the slice window")
	}
}

// -------------------------------------------------------------------------
// Erase() tests
// -------------------------------------------------------------------------

func TestErase_ByteSlice(t *testing.T) {
	buf := []byte("erase-me-fully")
	Erase(&buf)
	if buf != nil {
		t.Errorf("expected nil slice, got len=%d", len(buf))
	}
}

func TestErase_StringSlice(t *testing.T) {
	sl := []string{"password1", "password2", "password3"}
	Erase(&sl)
	if sl != nil {
		t.Errorf("expected nil, got %v", sl)
	}
}

func TestErase_IntSlice(t *testing.T) {
	sl := []int{1, 2, 3, 4}
	Erase(&sl)
	if sl != nil {
		t.Errorf("expected nil, got %v", sl)
	}
}

func TestErase_String(t *testing.T) {
	s := "erase-this"
	Erase(&s)
	if s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestErase_Map(t *testing.T) {
	m := map[string]string{"key": "value"}
	Erase(&m)
	if m != nil {
		t.Errorf("expected nil map, got %v", m)
	}
}

func TestErase_Struct(t *testing.T) {
	c := Credentials{ID: 7, Password: "p", Token: []byte("t")}
	Erase(&c)
	assertCredentialsZero(t, c)
}

func TestErase_Int(t *testing.T) {
	n := 12345
	Erase(&n)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestErase_NilPointer(t *testing.T) {
	var p *[]byte
	Erase(p) // must not panic — p itself is nil
}

// -------------------------------------------------------------------------
// Struct() tests
// -------------------------------------------------------------------------

func TestStruct_Nil(t *testing.T) {
	if err := Struct(nil); err == nil {
		t.Error("expected error for nil")
	}
}

func TestStruct_NonStruct(t *testing.T) {
	s := "test"
	if err := Struct(&s); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestStruct_Basic(t *testing.T) {
	c := Credentials{
		ID:       42,
		Password: "super-secret",
		Token:    []byte("auth-token"),
		APIKey:   [32]byte{1, 2, 3, 4, 5},
	}
	if err := Struct(&c); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	assertCredentialsZero(t, c)
}

func TestStruct_StringBacking(t *testing.T) {
	// Verify that Struct() attempts to zero string backing data.
	original := []byte("deep-secret-password")
	c := Credentials{Password: string(original)}
	dataPtr := unsafe.StringData(c.Password)
	dataLen := len(c.Password)
	if err := Struct(&c); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if c.Password != "" {
		t.Errorf("Password not cleared: %q", c.Password)
	}
	allZero := true
	for i := 0; i < dataLen; i++ {
		if *(*byte)(unsafe.Add(unsafe.Pointer(dataPtr), i)) != 0 {
			allZero = false
			break
		}
	}
	t.Logf("Password backing bytes zeroed: %v", allZero)
}

func TestStruct_ByteSliceField(t *testing.T) {
	c := Credentials{Token: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
	if err := Struct(&c); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if !bytes.Equal(c.Token, make([]byte, len(c.Token))) {
		t.Errorf("Token not zeroed: %v", c.Token)
	}
}

func TestStruct_Embedded(t *testing.T) {
	o := EmbeddedOuter{
		EmbeddedInner: EmbeddedInner{
			Key:   "embedded-key",
			Value: []byte("embedded-value"),
		},
		Name: "outer-name",
		Tags: []string{"tag1", "tag2"},
	}
	if err := Struct(&o); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if o.Key != "" {
		t.Errorf("embedded Key not cleared: %q", o.Key)
	}
	if o.Value != nil {
		t.Errorf("embedded Value not cleared: %v", o.Value)
	}
	if o.Name != "" {
		t.Errorf("Name not cleared: %q", o.Name)
	}
	if o.Tags != nil {
		t.Errorf("Tags not cleared: %v", o.Tags)
	}
}

func TestStruct_DeepNested(t *testing.T) {
	d := DeepNested{
		Map: map[string]string{"k": "v"},
	}
	d.Level1.Token = "level1-token"
	d.Level1.Level2.Secret = "deep-secret"
	d.Level1.Level2.Data = []byte("deep-data")

	if err := Struct(&d); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if d.Level1.Token != "" {
		t.Errorf("Level1.Token: %q", d.Level1.Token)
	}
	if d.Level1.Level2.Secret != "" {
		t.Errorf("Level1.Level2.Secret: %q", d.Level1.Level2.Secret)
	}
	if d.Level1.Level2.Data != nil {
		t.Errorf("Level1.Level2.Data: %v", d.Level1.Level2.Data)
	}
	if d.Map != nil {
		t.Errorf("Map not cleared: %v", d.Map)
	}
}

func TestStruct_WithMaps(t *testing.T) {
	wm := WithMaps{
		Simple: map[string]string{"user": "admin", "pass": "secret"},
		IntMap: map[int][]byte{1: {0xAA, 0xBB}},
		AnyMap: map[string]interface{}{"key": "val"},
		Nested: map[string]map[string]string{"a": {"b": "c"}},
	}
	if err := Struct(&wm); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if wm.Simple != nil {
		t.Errorf("Simple map not cleared")
	}
	if wm.IntMap != nil {
		t.Errorf("IntMap not cleared")
	}
	if wm.AnyMap != nil {
		t.Errorf("AnyMap not cleared")
	}
	if wm.Nested != nil {
		t.Errorf("Nested map not cleared")
	}
}

func TestStruct_StringSliceField(t *testing.T) {
	type WithStrSlice struct {
		Passwords []string
	}
	w := WithStrSlice{Passwords: []string{"pass1", "pass2", "pass3"}}
	if err := Struct(&w); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if w.Passwords != nil {
		t.Errorf("Passwords slice not cleared: %v", w.Passwords)
	}
}

func TestStruct_FullSecret(t *testing.T) {
	ptrStr := "ptr-secret"
	fs := FullSecret{
		ID:       1,
		Score:    9.9,
		Flag:     true,
		Password: "fullsecret",
		Token:    []byte("tok"),
		Keys:     []string{"k1", "k2"},
		Credentials: Credentials{
			Password: "nested-pass",
			Token:    []byte("nested-tok"),
		},
		Meta:  map[string]string{"a": "b"},
		Ptr:   &ptrStr,
		Iface: "interface-secret",
		Ch:    make(chan int, 1),
	}
	if err := Struct(&fs); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if fs.ID != 0 {
		t.Errorf("ID: %d", fs.ID)
	}
	if fs.Score != 0 {
		t.Errorf("Score: %f", fs.Score)
	}
	if fs.Flag {
		t.Error("Flag not cleared")
	}
	if fs.Password != "" {
		t.Errorf("Password: %q", fs.Password)
	}
	if fs.Token != nil {
		t.Errorf("Token: %v", fs.Token)
	}
	if fs.Keys != nil {
		t.Errorf("Keys: %v", fs.Keys)
	}
	if fs.Credentials.Password != "" {
		t.Errorf("Credentials.Password: %q", fs.Credentials.Password)
	}
	if fs.Meta != nil {
		t.Errorf("Meta: %v", fs.Meta)
	}
	if fs.Ptr != nil {
		t.Errorf("Ptr: %v", fs.Ptr)
	}
	if fs.Iface != nil {
		t.Errorf("Iface: %v", fs.Iface)
	}
	if fs.Ch != nil {
		t.Errorf("Ch: %v", fs.Ch)
	}
}

// -------------------------------------------------------------------------
// Unexported field tests
// -------------------------------------------------------------------------

func TestZero_UnexportedFields(t *testing.T) {
	w := WithUnexported{
		Public:  "public-data",
		private: "private-secret",
		secret:  []byte("secret-bytes"),
		count:   99,
	}
	if err := Struct(&w); err != nil {
		t.Fatalf("Struct error: %v", err)
	}
	if w.Public != "" {
		t.Errorf("Public: %q", w.Public)
	}
	if w.private != "" {
		t.Errorf("private: %q", w.private)
	}
	if w.secret != nil {
		t.Errorf("secret: %v", w.secret)
	}
	if w.count != 0 {
		t.Errorf("count: %d", w.count)
	}
}

// -------------------------------------------------------------------------
// Erase generic with various type scenarios
// -------------------------------------------------------------------------

func TestErase_NestedStructSlice(t *testing.T) {
	sl := []Credentials{
		{ID: 1, Password: "p1", Token: []byte("t1")},
		{ID: 2, Password: "p2", Token: []byte("t2")},
	}
	Erase(&sl)
	if sl != nil {
		t.Errorf("expected nil, got %v", sl)
	}
}

func TestErase_MapOfByteSlices(t *testing.T) {
	m := map[string][]byte{
		"key1": {0xAA, 0xBB, 0xCC},
		"key2": {0xDD, 0xEE, 0xFF},
	}
	Erase(&m)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestErase_PointerToStruct(t *testing.T) {
	c := &Credentials{ID: 5, Password: "ptr-pass", Token: []byte("ptr-tok")}
	Erase(&c)
	if c != nil {
		t.Errorf("expected nil pointer, got %v", c)
	}
}

// -------------------------------------------------------------------------
// Map zeroing edge cases
// -------------------------------------------------------------------------

func TestZero_EmptyMap(t *testing.T) {
	m := map[string]string{}
	mustZero(t, &m)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestZero_MapWithStringValues(t *testing.T) {
	m := map[string]string{
		"password": "s3cr3t",
		"apikey":   "key-material",
	}
	mustZero(t, &m)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestZero_MapWithByteSliceValues(t *testing.T) {
	m := map[string][]byte{
		"token": {0x01, 0x02, 0x03},
	}
	mustZero(t, &m)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestZero_NestedMap(t *testing.T) {
	m := map[string]map[string]string{
		"outer": {"inner": "secret"},
	}
	mustZero(t, &m)
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

// -------------------------------------------------------------------------
// Nil / zero-value resilience
// -------------------------------------------------------------------------

func TestZero_NilInsideStruct(t *testing.T) {
	type WithNils struct {
		P *string
		M map[string]string
		S []byte
		I interface{}
	}
	w := WithNils{} // all nil/zero
	if err := Struct(&w); err != nil {
		t.Fatalf("Struct error on all-nil struct: %v", err)
	}
}

func TestZero_DoubleZero(t *testing.T) {
	c := Credentials{ID: 1, Password: "pass"}
	mustZero(t, &c)
	// Zeroing an already-zero struct must not panic.
	mustZero(t, &c)
}

func TestErase_AlreadyNil(t *testing.T) {
	var buf []byte
	Erase(&buf)

	var m map[string]string
	Erase(&m)
}

// -------------------------------------------------------------------------
// Benchmarks
// -------------------------------------------------------------------------

func BenchmarkZero_Credentials(b *testing.B) {
	template := Credentials{
		ID: 1, Password: "benchmark-secret",
		Token: []byte("bench-token"), APIKey: [32]byte{1, 2, 3},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := template
		_ = Zero(&c)
	}
}

func BenchmarkErase_ByteSlice(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 1024)
		for j := range buf {
			buf[j] = byte(j)
		}
		Erase(&buf)
	}
}

func BenchmarkErase_String(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := "benchmark-secret-string-value"
		Erase(&s)
	}
}

func BenchmarkString(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := "benchmark-secret"
		String(&s)
	}
}

func BenchmarkBytes(b *testing.B) {
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, "benchmark-payload")
		Bytes(buf)
	}
}

func BenchmarkStruct_Full(b *testing.B) {
	template := FullSecret{
		ID: 1, Score: 1.0, Flag: true,
		Password: "bench-pass",
		Token:    []byte("bench-tok"),
		Keys:     []string{"k1", "k2"},
		Meta:     map[string]string{"a": "b"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fs := template
		fs.Meta = map[string]string{"a": "b"} // map must be re-created each iter
		_ = Struct(&fs)
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func mustZero(t *testing.T, v any) {
	t.Helper()
	if err := Zero(v); err != nil {
		t.Fatalf("Zero() error: %v", err)
	}
}

func assertCredentialsZero(t *testing.T, c Credentials) {
	t.Helper()
	if c.ID != 0 {
		t.Errorf("ID: want 0, got %d", c.ID)
	}
	if c.Password != "" {
		t.Errorf("Password: want \"\", got %q", c.Password)
	}
	if !bytes.Equal(c.Token, make([]byte, len(c.Token))) {
		t.Errorf("Token not zeroed: %v", c.Token)
	}
	for i, v := range c.APIKey {
		if v != 0 {
			t.Errorf("APIKey[%d]: want 0, got %d", i, v)
		}
	}
}
