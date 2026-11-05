package authentication

import "context"

// Operator is trusted only after access-token verification, never from a cookie or body.
type Operator struct{ Issuer, Subject string }

type OperatorVerifier interface {
	VerifyOperator(context.Context, string) (Operator, error)
}
