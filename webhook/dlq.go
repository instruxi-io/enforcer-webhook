package webhook

import (
	"context"
	"time"
)

// Entry is one parked webhook delivery. The service's Store decides physical
// storage; this is the shared shape the admin surface works with.
type Entry struct {
	ID        string    `json:"id"`
	WireTopic string    `json:"wire_topic"`
	EventID   string    `json:"event_id,omitempty"`
	Payload   string    `json:"-"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Store is the dead-letter persistence the owning service provides. Park is
// called when a downstream consumer exhausts retries; List/Take back the admin
// inspect + replay surface.
type Store interface {
	Park(ctx context.Context, wireTopic, eventID string, payload []byte, attempts int, lastErr string) error
	List(ctx context.Context, limit int) ([]Entry, error)
	// Take returns and removes the entry (single-use), for replay.
	Take(ctx context.Context, id string) (eventID, wireTopic, payload string, err error)
}

// Replay re-publishes a parked payload back onto its topic via the bus. A
// re-failed delivery simply re-parks downstream, so the cycle is self-correcting.
// Callers Take from the Store, then hand the result here.
func Replay(ctx context.Context, pub Publisher, ingestTenant, serviceUser, wireTopic, eventID, payload string) error {
	return pub.Publish(ctx, ingestTenant, serviceUser, wireTopic, eventID, payload,
		map[string]string{"x-webhook-replay": "true"})
}
