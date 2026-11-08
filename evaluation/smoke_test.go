package main

import "testing"

func TestSubmittedJobUsesVersionedCLIEnvelope(t *testing.T) {
	const id = "12345678-1234-4234-8234-123456789012"
	valid := `{"schema_version":1,"data":{"job":{"metadata":{"id":"` + id + `"}},"operation_id":"synthetic-operation"}}`
	if got, err := submittedJobID([]byte(valid)); err != nil || got != id {
		t.Fatalf("decoded ID = %q, %v", got, err)
	}
	for _, value := range []string{`{"data":{"job":{"metadata":{"id":"` + id + `"}}}}`, `{"schema_version":2,"data":{"job":{"metadata":{"id":"` + id + `"}}}}`, `{"schema_version":1,"job":{"metadata":{"id":"` + id + `"}}}`, valid + `{}`, `not JSON`} {
		if _, err := submittedJobID([]byte(value)); err == nil {
			t.Fatal("accepted an invalid CLI envelope")
		}
	}
}
