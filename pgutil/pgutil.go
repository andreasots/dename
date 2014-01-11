package pgutil

import "github.com/bmizerany/pq"

const ErrRetrySerializeable = "40001"
const ErrUniqueViolation = "23505"

func IsError(err error, code string) bool {
	if err == nil {
		return false
	}
	pqErr, ok := err.(pq.PGError)
	return ok && pqErr.Get('C') == code
}
