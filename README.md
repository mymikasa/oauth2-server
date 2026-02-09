# oauth2-server
oauth2-demo

## 1. 数据模型设计

### domain

``` go
// user.go
type User struct {
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    Password     string    `json:"-"`              // 不序列化到 JSON
    Email        string    `json:"email"`
    DisplayName  string    `json:"display_name"`
    CreatedAt    time.Time `json:"created_at"`
}

//client.go
type Client struct {
    ID           string    `json:"client_id"`
    Secret       string    `json:"client_secret"`   // 注册时返回一次
    Name         string    `json:"name"`            // 应用名称
    Description  string    `json:"description"`     // 应用描述
    RedirectURIs []string  `json:"redirect_uris"`   // 允许的重定向 URI 列表
    CreatedAt    time.Time `json:"created_at"`
}

// authcode.go
type AuthorizationCode struct {
	Code        string    `json:"code"`
	ClientId    int64     `json:"client_id"`
	UserId      string    `json:"user_id"`
	RedirectUri string    `json:"redirect_uri"`
	Scope       string    `json:"scope"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Used        bool      `json:"used_at"`
}

// token.go

type AccessToken struct {
    Token     string    `json:"access_token"`
    TokenType string    `json:"token_type"`        // 固定为 "Bearer"
    ClientID  string    `json:"client_id"`
    UserID    string    `json:"user_id"`
    Scope     string    `json:"scope"`
    ExpiresAt time.Time `json:"expires_at"`
    CreatedAt time.Time `json:"created_at"`
}

type RefreshToken struct {
    Token     string    `json:"refresh_token"`
    ClientID  string    `json:"client_id"`
    UserID    string    `json:"user_id"`
    ExpiresAt time.Time `json:"expires_at"`
    Revoked   bool      `json:"revoked"`           // 是否已撤销
    CreatedAt time.Time `json:"created_at"`
}
```

## 2. 存储接口设计

## 3. 核心业务逻辑设计

## 4. 核心业务逻辑设计

## 5. web接口设计

## 6. 配置文件设计

## 7. session 设计