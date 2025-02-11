package log

import (
	"errors"
	"fmt"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/configs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

/*
リクエストコンテキストに、zap.loggerを生成とセット
*/
func RequestLoggerMiddleware(logger *zap.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// リクエストスコープのロガーを作成/取得
			reqLogger := GetLogger(c)
			//リクエストログ
			reqLogger.Info("Request",
				zap.String("method", c.Request().Method),
				zap.String("path", c.Request().URL.Path),
				zap.Int("bytes_in", int(c.Request().ContentLength)),
				zap.Any("header", c.Request().Header),
			)

			// リクエスト処理の開始時間
			start := time.Now()
			err := next(c)
			duration := time.Since(start)

			// レスポンスログ
			reqLogger.Info("Response",
				zap.Int("status", c.Response().Status),
				zap.Duration("latency", duration),
			)
			return err
		}
	}
}

/*
コンテキストごとのloggerを取得。
ない場合は、クローンする
*/
func GetLogger(c echo.Context) *zap.Logger {
	if logger, ok := c.Get("logger").(*zap.Logger); ok && logger != nil {
		// logger.Debug("コンテキストからloggerを取得")
		return logger
	}
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	logger := gLogger.With(zap.String("request_id", requestID))
	logger.Debug("コンテキストにloggerがないため、生成してコンテキストにセット")
	c.Set("logger", logger) // コンテキストにロガーをセット
	return logger
}

// 大元のzap.logger
var gLogger *zap.Logger

func SetLogger(l *zap.Logger) {
	gLogger = l
}

func NewWanRunLogger() *zap.Logger {
	level := zap.NewAtomicLevel()
	// ログレベルを文字列から設定
	levelString := configs.FetchConfigStr("log.level")
	fmt.Println(levelString)
	err := level.UnmarshalText([]byte(levelString))
	if err != nil {
		level.SetLevel(zapcore.InfoLevel)
	}

	myConfig := zap.Config{
		Level:             level,
		Encoding:          "console",
		DisableStacktrace: false,
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "Time",
			LevelKey:       "Level",
			NameKey:        "Name",
			CallerKey:      "Caller",
			MessageKey:     "Msg",
			StacktraceKey:  "St",
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, _ := myConfig.Build()
	return logger
}

/*
loggerのテスト用
*/
func Test(c echo.Context) error {
	logger := GetLogger(c)
	logger.Info("Info message")
	gLogger.Info("glogger info message")
	err := errors.New("something went wrong")
	logger.Error("aaa", zap.Error(err))
	return nil
}
