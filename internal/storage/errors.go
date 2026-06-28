package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	security "github.com/torob/certhub/internal/crypto"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrNoRows = pgx.ErrNoRows

func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// SanitizeError removes PostgreSQL detail fields that may contain row values.
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		summary := "postgresql error"
		if strings.HasPrefix(pgErr.Code, "23") {
			summary = "postgresql constraint violation"
		}
		if pgErr.Code != "" {
			return fmt.Errorf("%s: SQLSTATE %s", summary, pgErr.Code)
		}
		return errors.New(summary)
	}
	redacted := security.RedactString(err.Error())
	if redacted == "" {
		return errors.New("postgresql error")
	}
	return errors.New(redacted)
}
