package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	leaseNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	leaseOwnerRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}/[a-z][a-z0-9_.:-]{0,63}$`)
	leaseTokenRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type Lease struct {
	Name        string
	LockedBy    string
	LockedUntil time.Time
}

type LeaseGrant struct {
	Name        string
	LockedBy    string
	LockedUntil time.Time
	Generation  int64
	Token       string
}

func TryAdvisoryXactLock(ctx context.Context, tx Tx, key int64) (bool, error) {
	var acquired bool
	if err := tx.QueryRow(ctx, `select pg_try_advisory_xact_lock($1)`, key).Scan(&acquired); err != nil {
		return false, fmt.Errorf("try transaction advisory lock: %w", SanitizeError(err))
	}
	return acquired, nil
}

func AcquireLease(ctx context.Context, db QueryRower, lease Lease) (LeaseGrant, bool, error) {
	if err := validateLease(lease); err != nil {
		return LeaseGrant{}, false, err
	}
	token, err := newLeaseToken()
	if err != nil {
		return LeaseGrant{}, false, err
	}
	var grant LeaseGrant
	err = db.QueryRow(ctx, `
insert into certhub_leases (name, locked_by, locked_until, generation, lease_token, updated_at)
values ($1, $2, $3, 1, $4::uuid, now())
on conflict (name) do update
set locked_by = excluded.locked_by,
    locked_until = excluded.locked_until,
    generation = certhub_leases.generation + 1,
    lease_token = excluded.lease_token,
    updated_at = now()
where certhub_leases.locked_until <= now()
   or certhub_leases.locked_by = excluded.locked_by
returning name, locked_by, locked_until, generation, lease_token::text`, lease.Name, lease.LockedBy, lease.LockedUntil, token).Scan(&grant.Name, &grant.LockedBy, &grant.LockedUntil, &grant.Generation, &grant.Token)
	if err != nil {
		if errors.Is(err, ErrNoRows) || isNoRows(err) {
			return LeaseGrant{}, false, nil
		}
		return LeaseGrant{}, false, fmt.Errorf("acquire lease: %w", SanitizeError(err))
	}
	return grant, true, nil
}

func ReleaseLease(ctx context.Context, db Execer, grant LeaseGrant) (bool, error) {
	if err := validateLeaseGrant(grant); err != nil {
		return false, err
	}
	tag, err := db.Exec(ctx, `
update certhub_leases
set locked_by = null,
    locked_until = '-infinity'::timestamptz,
    lease_token = null,
    updated_at = now()
where name = $1
  and locked_by = $2
  and generation = $3
  and lease_token = $4::uuid`, grant.Name, grant.LockedBy, grant.Generation, grant.Token)
	if err != nil {
		return false, fmt.Errorf("release lease: %w", SanitizeError(err))
	}
	return tag.RowsAffected() == 1, nil
}

func validateLease(lease Lease) error {
	if lease.Name == "" || !leaseNameRE.MatchString(lease.Name) {
		return errors.New("lease name must be a stable lowercase identifier")
	}
	if lease.LockedBy == "" || !leaseOwnerRE.MatchString(lease.LockedBy) {
		return errors.New("lease owner must be a non-secret lowercase worker/process identifier")
	}
	if lease.LockedUntil.IsZero() {
		return errors.New("lease locked_until is required")
	}
	if !lease.LockedUntil.After(time.Now()) {
		return errors.New("lease locked_until must be in the future")
	}
	return nil
}

func validateLeaseGrant(grant LeaseGrant) error {
	if grant.Name == "" || !leaseNameRE.MatchString(grant.Name) {
		return errors.New("lease name must be a stable lowercase identifier")
	}
	if grant.LockedBy == "" || !leaseOwnerRE.MatchString(grant.LockedBy) {
		return errors.New("lease owner must be a non-secret lowercase worker/process identifier")
	}
	if grant.Generation < 1 {
		return errors.New("lease generation is required")
	}
	if grant.Token == "" || !leaseTokenRE.MatchString(grant.Token) {
		return errors.New("lease token is required")
	}
	return nil
}

func newLeaseToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("lease token entropy unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:]), nil
}
