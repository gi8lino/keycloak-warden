package model

import (
	"encoding/json"
	"testing"
)

func TestRequestJSON(t *testing.T) {
	t.Parallel()

	t.Run("manual ban duration is a string", func(t *testing.T) {
		t.Parallel()

		request := CreateBanRequest{
			IP:       "203.0.113.42",
			Duration: "15m0s",
			Reason:   "Investigation",
		}

		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(encoded), `{"ipAddress":"203.0.113.42","duration":"15m0s","reason":"Investigation"}`; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}

		var decoded CreateBanRequest
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != request {
			t.Fatalf("got %+v, want %+v", decoded, request)
		}
	})

	t.Run("explicit delivery retry", func(t *testing.T) {
		t.Parallel()

		request := RetryRequest{
			DecisionID:  "decision-one",
			Revision:    3,
			Destination: "webhook.receiver",
			Actor:       "operator",
		}

		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(encoded), `{"decisionId":"decision-one","revision":3,"destination":"webhook.receiver","actor":"operator"}`; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}

		var decoded RetryRequest
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != request {
			t.Fatalf("got %+v, want %+v", decoded, request)
		}
	})

	t.Run("queued retry response", func(t *testing.T) {
		t.Parallel()

		encoded, err := json.Marshal(RetryResponse{Queued: true})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(encoded), `{"queued":true}`; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})
}
