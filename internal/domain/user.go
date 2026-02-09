package domain

import "time"

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Email     string    `json:"email"`
	NickName  string    `json:"nick_name"`
	CreatedAt time.Time `json:"created_at"`
}
