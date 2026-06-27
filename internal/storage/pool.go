package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultConnectTimeout = 5 * time.Second

type Config struct {
	URL            string
	ConnectTimeout time.Duration
}

type Pool struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, cfg Config) (*Pool, error) {
	if cfg.URL == "" {
		return nil, errors.New("postgresql url is required")
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("postgresql pool config: %w", SanitizeError(err))
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgresql pool open: %w", SanitizeError(err))
	}
	return &Pool{pool: pool}, nil
}

func (p *Pool) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

func (p *Pool) Ping(ctx context.Context) error {
	if p == nil || p.pool == nil {
		return errors.New("postgresql pool is not open")
	}
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgresql ping: %w", SanitizeError(err))
	}
	return nil
}

func (p *Pool) Begin(ctx context.Context) (Tx, error) {
	if p == nil || p.pool == nil {
		return nil, errors.New("postgresql pool is not open")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgresql begin: %w", SanitizeError(err))
	}
	return sanitizedTx{tx: tx}, nil
}

func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if p == nil || p.pool == nil {
		return pgconn.CommandTag{}, errors.New("postgresql pool is not open")
	}
	tag, err := p.pool.Exec(ctx, sql, args...)
	if err != nil {
		return tag, fmt.Errorf("postgresql exec: %w", SanitizeError(err))
	}
	return tag, nil
}

func (p *Pool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return sanitizedRow{row: p.pool.QueryRow(ctx, sql, args...)}
}

func (p *Pool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if p == nil || p.pool == nil {
		return nil, errors.New("postgresql pool is not open")
	}
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgresql query: %w", SanitizeError(err))
	}
	return sanitizedRows{rows: rows}, nil
}

type sanitizedTx struct {
	tx pgx.Tx
}

func (s sanitizedTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := s.tx.Exec(ctx, sql, args...)
	if err != nil {
		return tag, fmt.Errorf("postgresql exec: %w", SanitizeError(err))
	}
	return tag, nil
}

func (s sanitizedTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return sanitizedRow{row: s.tx.QueryRow(ctx, sql, args...)}
}

func (s sanitizedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := s.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgresql query: %w", SanitizeError(err))
	}
	return sanitizedRows{rows: rows}, nil
}

func (s sanitizedTx) Commit(ctx context.Context) error {
	if err := s.tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgresql commit: %w", SanitizeError(err))
	}
	return nil
}

func (s sanitizedTx) Rollback(ctx context.Context) error {
	if err := s.tx.Rollback(ctx); err != nil {
		return fmt.Errorf("postgresql rollback: %w", SanitizeError(err))
	}
	return nil
}

type sanitizedRow struct {
	row pgx.Row
}

func (s sanitizedRow) Scan(dest ...any) error {
	if err := s.row.Scan(dest...); err != nil {
		return SanitizeError(err)
	}
	return nil
}

type sanitizedRows struct {
	rows pgx.Rows
}

func (s sanitizedRows) Close() {
	s.rows.Close()
}

func (s sanitizedRows) Err() error {
	return SanitizeError(s.rows.Err())
}

func (s sanitizedRows) CommandTag() pgconn.CommandTag {
	return s.rows.CommandTag()
}

func (s sanitizedRows) FieldDescriptions() []pgconn.FieldDescription {
	return s.rows.FieldDescriptions()
}

func (s sanitizedRows) Next() bool {
	return s.rows.Next()
}

func (s sanitizedRows) Scan(dest ...any) error {
	if err := s.rows.Scan(dest...); err != nil {
		return SanitizeError(err)
	}
	return nil
}

func (s sanitizedRows) Values() ([]any, error) {
	values, err := s.rows.Values()
	if err != nil {
		return nil, SanitizeError(err)
	}
	return values, nil
}

func (s sanitizedRows) RawValues() [][]byte {
	return s.rows.RawValues()
}

func (s sanitizedRows) Conn() *pgx.Conn {
	return s.rows.Conn()
}

type Beginner interface {
	Begin(context.Context) (Tx, error)
}

type Execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type QueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type DBTX interface {
	Execer
	QueryRower
	Queryer
}

type Tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

const rollbackTimeout = 5 * time.Second

func WithTx(ctx context.Context, db Beginner, fn func(context.Context, Tx) error) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			rollbackWithFreshContext(ctx, tx)
			panic(p)
		}
		if err != nil {
			rollbackWithFreshContext(ctx, tx)
		}
	}()
	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func rollbackWithFreshContext(ctx context.Context, tx Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	if rollbackCtx.Err() != nil {
		cancel()
		rollbackCtx, cancel = context.WithTimeout(context.Background(), rollbackTimeout)
	}
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}
