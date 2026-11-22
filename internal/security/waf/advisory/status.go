// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

// Status is what the dashboard is told about the exchange.
type Status struct {
	// Configured is whether there is a worker to ask. With none, a route's
	// switch does nothing, and the dashboard says so.
	Configured bool `json:"configured"`
	// Worker is the scheme and host batches go to. Never the token.
	Worker string `json:"worker,omitempty"`
	Mode   Mode   `json:"mode,omitempty"`

	QueueCapacity int `json:"queueCapacity"`
	Queued        int `json:"queued"`

	// Offered is every sample the request path built; Dropped the ones a
	// full queue turned away; Failed the ones lost to a worker that did not
	// answer; Sent the ones it did answer for.
	Offered uint64 `json:"offered"`
	Dropped uint64 `json:"dropped"`
	Sent    uint64 `json:"sent"`
	Failed  uint64 `json:"failed"`
	// Flagged is how many samples the worker had something against, and
	// Unmatched how many verdicts answered nothing it was asked, or a sample
	// it had already answered for.
	Flagged   uint64 `json:"flagged"`
	Unmatched uint64 `json:"unmatched"`

	// LastContact is when the worker last answered, in Unix seconds, and 0
	// when it never has. LastError is why the last batch was lost, and
	// empty when it was not.
	LastContact int64  `json:"lastContact"`
	LastError   string `json:"lastError,omitempty"`
}

// Status reports where the exchange stands.
func (q *Queue) Status() Status {
	if q.ch == nil {
		return Status{}
	}
	st := Status{
		Configured:    true,
		Worker:        q.endpoint,
		Mode:          q.cfg.Mode,
		QueueCapacity: cap(q.ch),
		Queued:        len(q.ch),
		Offered:       q.offered.Load(),
		Dropped:       q.dropped.Load(),
		Sent:          q.sent.Load(),
		Failed:        q.failed.Load(),
		Flagged:       q.flagged.Load(),
		Unmatched:     q.unmatched.Load(),
		LastContact:   q.lastContact.Load(),
	}
	if e := q.lastError.Load(); e != nil {
		st.LastError = printable(*e, maxReason)
	}
	return st
}
