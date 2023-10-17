// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package fileconsumer // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer"

import (
	"context"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/internal/reader"
)

type closeImmediately struct{}

func newRoller() roller {
	return &closeImmediately{}
}

func (r *closeImmediately) readLostFiles(ctx context.Context, newReaders []*reader.Reader) {
	return
}

func (r *closeImmediately) roll(_ context.Context, newReaders []*reader.Reader) {
	for _, newReader := range newReaders {
		newReader.Close()
	}
}

func (r *closeImmediately) cleanup() {
	return
}
