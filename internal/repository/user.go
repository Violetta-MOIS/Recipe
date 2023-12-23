package repository

import (
	"context"
	"fmt"
)

type User struct {
	ID       int    `json:"id" db:"id"`
	Name     string `json:"name" db:"name"`
	Email    string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
}

func (r *Repository) Login(ctx context.Context, email, hashedPassword string) (u User, err error) {

	row := r.pool.QueryRow(ctx, `select id, name, email, password from Users where email = $1 AND password = $2`, email, hashedPassword)
	if err != nil {
		err = fmt.Errorf("failed to query data: %w", err)
		return
	}

	err = row.Scan(&u.ID, &u.Name, &u.Email, &u.Password)
	if err != nil {
		err = fmt.Errorf("failed to query data: %w", err)
		return
	}

	return
}

func (r *Repository) AddNewUser(ctx context.Context, name, email, hashedPassword string) (err error) {
	_, err = r.pool.Exec(ctx, `insert into users (Name, Email, Password) values ($1, $2, $3)`, name, email, hashedPassword)
	if err != nil {
		err = fmt.Errorf("failed to exec data: %w", err)
		return
	}

	return
}

func (r *Repository) GetUserByID(ctx context.Context, userID int) (User, error) {
	var user User

	query := "SELECT name, email FROM users WHERE id = $1"
	err := r.pool.QueryRow(ctx, query, userID).Scan(&user.Name, &user.Email)
	if err != nil {
		return User{}, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

func (r *Repository) UpdateAbout(ctx context.Context, userID int, about string) error {
	query := "INSERT INTO user_info (user_id, about) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET about = excluded.about"
	_, err := r.pool.Exec(ctx, query, userID, about)
	if err != nil {
		return fmt.Errorf("failed to update user about: %w", err)
	}
	return nil
}

func (r *Repository) GetAboutByID(ctx context.Context, userID int) (string, error) {
	var about string

	row := r.pool.QueryRow(ctx, "SELECT about FROM user_info WHERE user_id = $1", userID)
	err := row.Scan(&about)
	if err != nil {
		return "", fmt.Errorf("failed to get user about: %w", err)
	}

	return about, nil
}

func (r *Repository) BuyStock(ctx context.Context, userID int, stockID string) error {

	return nil
}

func (r *Repository) GetPurchasedStocksByID(ctx context.Context, userID int) ([]string, error) {
	var purchasedStocks []string

	row := r.pool.QueryRow(ctx, "SELECT purchased_stocks FROM user_info WHERE user_id = $1", userID)
	err := row.Scan(&purchasedStocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get user's purchased stocks: %w", err)
	}

	return purchasedStocks, nil
}
