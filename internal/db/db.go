package db

import (
	"fmt"
	"log"

	_ "github.com/joho/godotenv"
	"github.com/wanrun-develop/wanrun/configs"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDB() (*gorm.DB, error) {
	config := configs.DbInfo()
	fmt.Printf("DB info: %+v\n", *config)

	postgresUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		config.PostgresUser(),
		config.PostgresPassword(),
		config.PostgresHost(),
		config.PostgresPort(),
		config.PostgresDB())

	// logレベルの取得
	logLevel := getLoggerLevel()

	db, err := gorm.Open(postgres.Open(postgresUrl), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})

	if err != nil {
		return db, err
	}
	log.Println("Connected to DB")
	return db, nil
}

func CloseDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	if err := sqlDB.Close(); err != nil {
		return err
	}
	return nil
}

func getLoggerLevel() logger.LogLevel {
	stage := configs.FetchConfigStr("STAGE")
	// 環境に応じてログレベルを設定
	switch stage {
	case "prod":
		return logger.Error // 本番環境ではエラーのみ記録
	case "develop":
		return logger.Info // 開発環境では詳細な情報を記録
	default:
		return logger.Warn // デフォルトで警告以上を記録
	}
}
