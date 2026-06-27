// Package postgres embeds Certhub PostgreSQL SQL migrations.
package postgres

import "embed"

// FS contains the SQL migration files shipped with the server binary.
//
//go:embed *.sql
var FS embed.FS
