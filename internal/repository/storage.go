package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
)

func InitDBConn(ctx context.Context, host, port, user, password, dbname string) (dbpool *pgxpool.Pool, err error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)

	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		err = fmt.Errorf("failed to parse pg config: %w", err)
		return
	}


	dbpool, err = pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		err = fmt.Errorf("failed to connect config: %w", err)
		return
	}

	return
}
