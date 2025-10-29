package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

// 新增配置结构体
type Config struct {
	JWTSecret     string `yaml:"jwt_secret"`
	JWTUsers      string `yaml:"jwt_users"`
	FileStorePath string `yaml:"file_store_path"`
	Host          string `yaml:"host"`
	Port          string `yaml:"port"`
}

var (
	configPath string
	config     Config
	fileDir    string
)

func init() {
	// 解析命令行参数，默认配置文件路径为config.yaml
}

func write(data interface{}, userID string) (string, int) {
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return "Internal server error", 500
	}

	filePath := filepath.Join(fileDir, userID+".json")
	err = os.WriteFile(filePath, jsonBody, 0644)
	if err != nil {
		return "Internal server error", 500
	}

	return "ok", 200
}

func read(userID string) (interface{}, int) {
	filePath := filepath.Join(fileDir, userID+".json")

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "File not found", 404
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "Internal server error", 500
	}

	var result map[string]interface{}
	if err := json.Unmarshal(fileData, &result); err != nil {
		return "Internal server error", 500
	}

	return result, 200
}

func main() {
	flag.StringVar(&configPath, "config", "config.yaml", "指定YAML配置文件路径")
	flag.StringVar(&configPath, "c", "config.yaml", "指定YAML配置文件路径")
	flag.Parse()

	if configPath == "" {
		log.Fatalf("指定配置文件")
	}
	// 加载环境变量（ fallback 用 ）
	godotenv.Load()

	// 优先加载YAML配置
	yamlFile, err := os.ReadFile(configPath)
	if err == nil {
		if err := yaml.Unmarshal(yamlFile, &config); err != nil {
			log.Fatalf("YAML配置解析失败: %v", err)
		}
	} else {
		log.Printf("配置文件%s不存在, 读取环境变量", configPath)
		// 回退到环境变量
		config = Config{
			JWTSecret:     os.Getenv("JWT_SECRET"),
			JWTUsers:      os.Getenv("JWT_USERS"),
			FileStorePath: os.Getenv("FILE_STORE_PATH"),
			Host:          os.Getenv("HOST"),
			Port:          os.Getenv("PORT"),
		}
	}

	// 校验必填配置
	if config.JWTSecret == "" {
		log.Fatal("JWT_SECRET未在配置文件或环境变量中设置")
	}

	// 设置文件存储路径
	fileDir = config.FileStorePath

	// 初始化Gin并替换默认日志中间件
	router := gin.New()
	router.Use(gin.Recovery()) // 保留崩溃恢复中间件

	// 自定义详细日志中间件
	router.Use(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		clientIP := c.ClientIP()

		c.Next() // 处理请求

		// 记录响应信息
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		userID := c.GetString("userID")
		errorMsg := c.Errors.ByType(gin.ErrorTypePrivate).String()

		log.Printf(
			"[REQUEST] %s | %s | %s | %d | %s | UserID: %s | Error: %s",
			time.Now().Format("2006-01-02 15:04:05"),
			clientIP,
			method,
			path,
			statusCode,
			latency,
			userID,
			errorMsg,
		)
	})

	// JWT中间件
	authMiddleware := func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"status": "error", "message": "Unauthorized!"})
			c.Abort()
			return
		}

		// 移除 "Bearer " 前缀
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.JWTSecret), nil // 使用配置中的密钥
		})

		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"status": "error", "message": "Unauthorized!"})
			c.Abort()
			return
		}

		// 获取用户ID
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if userID, exists := claims["id"]; exists {
				c.Set("userID", userID.(string))
			} else {
				c.JSON(401, gin.H{"status": "error", "message": "Invalid token!"})
				c.Abort()
				return
			}
		}

		c.Next()
	}

	// 用户验证中间件
	userValidationMiddleware := func(c *gin.Context) {
		userID := c.GetString("userID")
		allowedUsers := strings.Split(config.JWTUsers, ",") // 使用配置中的用户列表

		allowed := false
		for _, user := range allowedUsers {
			if user == userID {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(401, gin.H{"status": "error", "message": "Unauthorized!"})
			c.Abort()
			return
		}

		c.Next()
	}

	// 路由定义
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// API路由组
	api := router.Group("/api")
	{
		api.Use(authMiddleware, userValidationMiddleware)

		api.GET("/sync", func(c *gin.Context) {
			userID := c.GetString("userID")
			result, status := read(userID)

			if status == 200 {
				c.JSON(status, result)
			} else {
				c.String(status, result.(string))
			}
		})

		api.PUT("/sync", func(c *gin.Context) {
			userID := c.GetString("userID")

			var data interface{}
			if err := c.BindJSON(&data); err != nil {
				c.JSON(400, gin.H{"status": "error", "message": "Invalid JSON"})
				return
			}

			result, status := write(data, userID)
			c.String(status, result)
		})

		api.POST("/sync", func(c *gin.Context) {
			c.String(200, "test ok")
		})
	}

	// 启动服务器
	router.Run(config.Host + ":" + config.Port) // 使用配置中的地址
}
