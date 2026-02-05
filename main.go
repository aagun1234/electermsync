package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelError = "error"
)

func getLogLevelPriority(level string) int {
	switch strings.ToLower(level) {
	case LogLevelDebug:
		return 0
	case LogLevelInfo:
		return 1
	case LogLevelError:
		return 2
	default:
		return 1 // Default to Info
	}
}

func logWithLevel(level string, format string, v ...interface{}) {
	if getLogLevelPriority(level) >= getLogLevelPriority(config.LogLevel) {
		log.Printf("["+strings.ToUpper(level)+"] "+format, v...)
	}
}

// 新增配置结构体
type Config struct {
	JWTSecret     string   `yaml:"jwt_secret"`
	JWTUsers      string   `yaml:"jwt_users"`
	FileStorePath string   `yaml:"file_store_path"`
	Listen        string   `yaml:"listen"`
	ACLWhitelist  []string `yaml:"acl_whitelist"`
	SSLCert       string   `yaml:"ssl_cert"`
	SSLKey        string   `yaml:"ssl_key"`
	LogLevel      string   `yaml:"log_level"`
	LogPath       string   `yaml:"log_path"`
}

var (
	configPath string
	config     Config
	fileDir    string
)

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
	flag.StringVar(&configPath, "config", "config.yaml", "config file path")
	flag.StringVar(&configPath, "c", "config.yaml", "config file path")
	flag.Parse()

	if configPath == "" {
		log.Fatalf("config file path not specified")
	}
	// 加载环境变量（ fallback 用 ）
	godotenv.Load()

	// 优先加载YAML配置
	yamlFile, err := os.ReadFile(configPath)
	if err == nil {
		if err := yaml.Unmarshal(yamlFile, &config); err != nil {
			log.Fatalf("YAML config parse failed: %v", err)
		}
	} else {
		logWithLevel(LogLevelInfo, "config file %s not found, fallback to env", configPath)
		// 回退到环境变量
		config = Config{
			JWTSecret:     os.Getenv("JWT_SECRET"),
			JWTUsers:      os.Getenv("JWT_USERS"),
			FileStorePath: os.Getenv("FILE_STORE_PATH"),
			Listen:        os.Getenv("LISTEN"),
			SSLCert:       os.Getenv("SSL_CERT"),
			SSLKey:        os.Getenv("SSL_KEY"),
			LogLevel:      os.Getenv("LOG_LEVEL"),
			LogPath:       os.Getenv("LOG_PATH"),
		}
	}

	// 设置默认监听地址
	if config.Listen == "" {
		config.Listen = "0.0.0.0:8080"
	}

	// 设置默认日志等级
	if config.LogLevel == "" {
		config.LogLevel = LogLevelInfo
	}

	// 初始化日志输出
	var logWriters []io.Writer
	logWriters = append(logWriters, os.Stdout)

	if config.LogPath != "" {
		logFile, err := os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		logWriters = append(logWriters, logFile)
	}

	multiWriter := io.MultiWriter(logWriters...)
	log.SetOutput(multiWriter)

	// 设置Gin日志输出
	gin.DefaultWriter = multiWriter

	// 校验必填配置
	if config.JWTSecret == "" {
		log.Fatal("JWT_SECRET not configed")
	}

	// 设置文件存储路径
	fileDir = config.FileStorePath

	// 初始化Gin并替换默认日志中间件
	router := gin.New()
	router.Use(gin.Recovery()) // 保留崩溃恢复中间件

	// IP匹配函数
	isIPAllowed := func(clientIPStr string, whitelist []string) bool {
		if len(whitelist) == 0 {
			return true // 如果没有配置白名单，允许所有访问
		}

		clientIP := net.ParseIP(clientIPStr)
		if clientIP == nil {
			return false
		}

		for _, pattern := range whitelist {
			// 1. 处理精确匹配
			patternIP := net.ParseIP(pattern)
			if patternIP != nil {
				if patternIP.Equal(clientIP) {
					return true
				}
				continue
			}

			// 2. 处理 CIDR (包括 0.0.0.0/0, ::/0)
			if strings.Contains(pattern, "/") {
				_, ipNet, err := net.ParseCIDR(pattern)
				if err == nil && ipNet.Contains(clientIP) {
					return true
				}
				continue
			}

			// 3. 处理通配符 (如 192.168.1.*) - 仅限 IPv4
			if strings.Contains(pattern, "*") {
				patternParts := strings.Split(pattern, ".")
				ipParts := strings.Split(clientIPStr, ".")

				if len(patternParts) == 4 && len(ipParts) == 4 {
					match := true
					for i := 0; i < 4; i++ {
						if patternParts[i] != "*" && patternParts[i] != ipParts[i] {
							match = false
							break
						}
					}
					if match {
						return true
					}
				}
				continue
			}
		}

		return false
	}

	router.Use(func(c *gin.Context) {
		clientIP := c.ClientIP()

		if !isIPAllowed(clientIP, config.ACLWhitelist) {
			logWithLevel(LogLevelError, "Access denied for IP: %s", clientIP)
			c.JSON(403, gin.H{"status": "error", "message": "Access denied"})
			c.Abort()
			return
		}

		c.Next()
	})

	// 详细日志中间件
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
		if errorMsg == "" {

			logWithLevel(
				LogLevelInfo,
				"[REQUEST] %s | %s | %s | %s | %d | %s | UserID: %s ",
				time.Now().Format("2006-01-02 15:04:05"),
				clientIP,
				method,
				path,
				statusCode,
				latency,
				userID,
			)
		} else {
			logWithLevel(
				LogLevelError,
				"[REQUEST] %s | %s | %s | %s | %d | %s | UserID: %s | Error: %s",
				time.Now().Format("2006-01-02 15:04:05"),
				clientIP,
				method,
				path,
				statusCode,
				latency,
				userID,
				errorMsg,
			)
		}
	})

	// JWT中间件
	authMiddleware := func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"status": "error", "message": "Unauthorized!"})
			c.Abort()
			logWithLevel(
				LogLevelError,
				"[JWT] %s Invalid token ",
				time.Now().Format("2006-01-02 15:04:05"),
			)
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
			logWithLevel(
				LogLevelError,
				"[JWT] %s Invalid token %s",
				time.Now().Format("2006-01-02 15:04:05"),
				tokenString,
			)
			return
		}

		// 获取用户ID
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if userID, exists := claims["id"]; exists {
				c.Set("userID", userID.(string))
			} else {
				c.JSON(401, gin.H{"status": "error", "message": "Invalid token!"})
				c.Abort()
				logWithLevel(
					LogLevelError,
					"[JWT] %s Invalid token %s",
					time.Now().Format("2006-01-02 15:04:05"),
					tokenString,
				)
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
		c.String(200, "GET ok")
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

		api.POST("/test", func(c *gin.Context) {
			c.String(200, "POST ok")
		})
	}

	// 启动服务器
	if config.SSLCert != "" && config.SSLKey != "" {
		logWithLevel(LogLevelInfo, "Starting HTTPS server on %s", config.Listen)
		if err := router.RunTLS(config.Listen, config.SSLCert, config.SSLKey); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	} else {
		logWithLevel(LogLevelInfo, "Starting HTTP server on %s", config.Listen)
		if err := router.Run(config.Listen); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}
}
