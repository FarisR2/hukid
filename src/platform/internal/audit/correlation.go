// Package audit carries server-generated correlation, never request credentials.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type correlationKey struct{}

func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:]), nil
}
func WithCorrelation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}
func Correlation(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}
