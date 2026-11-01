package event

// Encode serializa um valor no mesmo formato JSON usado nos registros.
func Encode(v any) []byte {
	return appendValue(nil, v)
}
