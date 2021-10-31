package logger

import (
	"context"
	"fmt"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func init() {
	config := zap.NewDevelopmentConfig()
	config.Encoding = "console"
	config.DisableStacktrace = true
	initedLogger, err := config.Build()
	if err != nil {
		panic(fmt.Errorf("cant init zap logger: %w", err))
	}
	logger = initedLogger.Sugar()
}

func FromContext(_ context.Context) *zap.SugaredLogger {
	return logger
}

func Close() {
	logger.Sync()
}
