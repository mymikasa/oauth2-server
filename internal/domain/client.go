package domain

import "time"

type Client struct {
	ID          string    `json:"id"`
	Secret      string    `json:"secret"`
	Name        string    `json:"name"`         // 应用名称
	Description string    `json:"description"`  // 应用描述
	RedirectURI string    `json:"redirect_uri"` // 允许的重定向 URI
	CreatedAt   time.Time `json:"created_at"`
	LogoUrl     string    `json:"logo_url"`
}
