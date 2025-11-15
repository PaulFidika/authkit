package migrations

import (
	"embed"

	"github.com/uptrace/bun/migrate"
)

//go:embed *.sql
var migrationFS embed.FS

// FS exposes the embedded SQL for external runners.
var FS = migrationFS

// Migrations is a bun/migrate registry for this module.
var Migrations = migrate.NewMigrations()

func init() {
	// Discover SQL migrations from embedded filesystem.
	_ = Migrations.Discover(migrationFS)
}
