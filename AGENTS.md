# AGENTS.md

## 构建 / 检查 / 测试命令

### 构建
```bash
go build ./...
go build -o oauth2-server ./cmd/server
```

### 代码检查
```bash
go fmt ./...
go vet ./...
golangci-lint run  # 如果已安装
```

### 测试
```bash
go test ./...                    # 运行所有测试
go test -v ./...                 # 运行测试并显示详细输出
go test -race ./...              # 运行测试并检测竞态条件
go test ./internal/domain        # 运行指定包的测试
go test -run TestUser ./...      # 运行指定的测试函数
go test -run TestUser.* ./...    # 运行匹配模式的测试
```

## 代码风格指南

### 项目结构
- `internal/domain/` - 领域模型和实体（纯数据结构）
- `internal/repository/dao/` - 数据访问接口和实现
- `internal/service/` - 业务逻辑和服务层

### 导入组织
1. 标准库导入在前
2. 第三方库导入居中
3. 内部包导入在后
4. 每个导入组之间用空行分隔
5. 使用绝对导入并包含模块前缀

```go
import (
    "time"

    "github.com/some/lib"

    "github.com/mymikasa/oauth2-server/internal/domain"
)
```

### 命名规范
- **包名**：小写，单词，描述性（如 `domain`、`service`、`dao`）
- **导出类型**：大驼峰（如 `User`、`AccessToken`、`Client`）
- **未导出类型**：小写（很少使用，如需导出则使用大驼峰）
- **导出字段**：大驼峰（如 `ID`、`Username`、`CreatedAt`）
- **未导出字段**：小驼峰或小写（如 `password`、`userId`）
- **函数**：导出用大驼峰，未导出用小驼峰
- **接口**：大驼峰，常以 `er` 结尾（如 `UserDao`、`Repository`）
- **常量**：大驼峰或全大写下划线（包级别）

### 类型定义
- 使用结构体标签标记 JSON：`json:"field_name"`（下划线命名）
- 可选字段使用 `omitempty`
- 使用 `-` 排除敏感字段的 JSON 序列化（如密码）

```go
type User struct {
    ID        string    `json:"id"`
    Username  string    `json:"username"`
    Password  string    `json:"-"`           // 不序列化
    Email     string    `json:"email"`
    CreatedAt time.Time `json:"created_at"`
}
```

### 错误处理
- 始终检查错误，不要忽略
- 显式返回错误，使用多返回值模式
- 使用 `fmt.Errorf` 或 `%w` 动词包装错误上下文
- 为领域特定错误定义自定义错误类型

```go
if err != nil {
    return fmt.Errorf("创建用户失败: %w", err)
}

// 或使用 errors.Is/As 处理类型化错误
if errors.Is(err, ErrUserNotFound) {
    return ErrUserNotFound
}
```

### 接口设计
- 在使用方包中定义接口（不在实现包中）
- 保持接口小而专注（接口隔离原则）
- 根据行为命名接口（如 `UserDao` 用于数据访问）

### 文件组织
- 每个目录一个包
- 相关的多个类型可在同一文件中
- 保持文件专注且相对较小（首选 <300 行）
- 文件以其主要类型命名（如 `user.go` 包含 `User`）

### 通用规范
- 所有时间戳使用 `time.Time`
- ID 使用 string 类型（UUID 或类似）
- 统一 JSON 命名：下划线命名
- 优先组合而非继承
- 避免全局状态
- 在 `*_test.go` 文件中编写测试代码
