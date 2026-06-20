package crypto

func BuildAAD(aadType string, fields ...[]byte) []byte {
	contextTag := []byte("skid:v3:" + aadType)

	allFields := make([][]byte, 0, len(fields)+1)
	allFields = append(allFields, contextTag)
	allFields = append(allFields, fields...)

	return ConcatBytes(allFields...)
}
