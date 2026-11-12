package requestcontext

import (
	"context"
	"sync"
)

type diagnosticsKey struct{}

type DiagnosticFields struct {
	RequestID      string
	UserID         string
	AuthResult     string
	DenylistResult string
	BanlistResult  string
	ErrorKind      string
	Dependency     string
	UpstreamCalled bool
	UpstreamStatus int
}

type Diagnostics struct {
	mu     sync.Mutex
	fields DiagnosticFields
}

func WithDiagnostics(ctx context.Context) (context.Context, *Diagnostics) {
	d := &Diagnostics{fields: DiagnosticFields{
		AuthResult: "not_required", DenylistResult: "not_checked", BanlistResult: "not_checked",
	}}
	return context.WithValue(ctx, diagnosticsKey{}, d), d
}

func UpdateDiagnostics(ctx context.Context, update func(*DiagnosticFields)) {
	d, ok := ctx.Value(diagnosticsKey{}).(*Diagnostics)
	if !ok {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	update(&d.fields)
}

func (d *Diagnostics) Snapshot() DiagnosticFields {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fields
}
