package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestErrorResponse_MarshalsToErrorKey(t *testing.T) {
	b, err := json.Marshal(NewError("boom"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); got != `{"error":"boom"}` {
		t.Fatalf("unexpected json: %s", got)
	}
}

func TestErrorResponse_OmitsEmptyDetails(t *testing.T) {
	b, _ := json.Marshal(NewError("boom"))
	if got := string(b); got != `{"error":"boom"}` {
		t.Fatalf("details should be omitted when empty, got: %s", got)
	}

	b, _ = json.Marshal(NewErrorWithDetails("boom", "root cause"))
	if got := string(b); got != `{"error":"boom","details":"root cause"}` {
		t.Fatalf("unexpected json with details: %s", got)
	}
}

func TestJSON_WritesEnvelopeWithoutAborting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	JSON(c, http.StatusNotFound, "not found")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if c.IsAborted() {
		t.Fatalf("JSON must not abort the chain")
	}
	var got ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.Error != "not found" {
		t.Fatalf("body error = %q, want %q", got.Error, "not found")
	}
}

func TestAbort_WritesEnvelopeAndAborts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Abort(c, http.StatusUnauthorized, "no token")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !c.IsAborted() {
		t.Fatalf("Abort must stop the handler chain")
	}
}
