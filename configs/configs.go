package configs

import (
	"fmt"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type DBInfoConfig struct {
	postgresUser     string
	postgresPassword string
	postgresHost     string
	postgresPort     string
	postgresDB       string
}

// 起動環境値
var profile string

func init() {
	profile = getEnv("APP_PROFILE", "dev")
	if err := LoadConfig(); err != nil {
		log.Fatalf("設定ファイルの読み込みに失敗しました: %s \n", err)
	}
	if CheckConfigChangeError() != nil {
		log.Fatalf("設定ファイルの読み込みに失敗しました: %s \n", configChangeError)
	}
}

var v *viper.Viper
var configChangeError error

/*
viperのload
*/
func LoadConfig() error {
	v = viper.New()
	v.SetConfigType("yaml")                  // 設定ファイルの形式
	v.SetConfigName("config-" + profile)     // 設定ファイル名を拡張子抜きで指定する
	v.AddConfigPath("./configs/")            // 設定ファイルの探索パスを指定する
	v.AddConfigPath(".")                     // 現在のワーキングディレクトリを探索することもできる
	if err := v.ReadInConfig(); err != nil { // 設定ファイルを探索して読み取る
		return err
	}
	v.WatchConfig()                           // 設定フィアルの変更を検知する
	v.OnConfigChange(func(e fsnotify.Event) { // 検知時に実行する関数の設定
		fmt.Println("設定ファイルが変更されました:", e.Name)
		if err := v.ReadInConfig(); err != nil { // 設定ファイルを探索して読み取る
			configChangeError = err
		}
	})
	bindEnvs()    // 環境変数
	setDefaults() // デフォルト設定

	return nil
}

// クロージャーのエラーを外に出すよう
func CheckConfigChangeError() error {
	return configChangeError
}

/*
viperに環境変数をバインド
*/
func bindEnvs() {
	_ = v.BindEnv("postgres.host", "POSTGRES_HOST")
	_ = v.BindEnv("postgres.port", "POSTGRES_PORT")
	_ = v.BindEnv("postgres.user", "POSTGRES_USER")
	_ = v.BindEnv("postgres.password", "POSTGRES_PASSWORD")
	_ = v.BindEnv("postgres.dbname", "POSTGRES_DB")
	_ = v.BindEnv("stage", "STAGE")
	_ = v.BindEnv("env", "ENV")
	_ = v.BindEnv("google.place.api.key", "GOOGLE_PLACE_API_KEY")
	_ = v.BindEnv("jwt.os.secret.key", "SECRET_KEY")                // jwt生成用の秘密鍵
	_ = v.BindEnv("jwt.exp.time", "JWT_EXP_TIME")                   // jwt生成用の有効期限（時間）
	_ = v.BindEnv("refresh.jwt.exp.time", "REFRESH_JWT_EXP_TIME")   // jwt生成用の有効期限（時間）
	_ = v.BindEnv("gcp.client.id", "GCP_CLIENT_ID")                 // oauthの際のgcp credentials
	_ = v.BindEnv("gcp.client.secret", "GCP_CLIENT_SECRET")         // oauthの際のgcp credentials
	_ = v.BindEnv("gcp.redirect.uri", "GCP_REDIRECT_URI")           // oauthの際のgcp credentials
	_ = v.BindEnv("aws.access.key", "AWS_ACCESS_KEY")               // awsのアクセスキー
	_ = v.BindEnv("aws.secret.access.key", "AWS_SECRET_ACCESS_KEY") // awsのシークレットアクセスキー
	_ = v.BindEnv("aws.s3.bucket.name", "AWS_S3_BUCKET_NAME")       // awsのbucket名
}

/*
ivperへのデフォルト設定（必要なやつ）
*/
func setDefaults() {
	v.SetDefault("postgres.host", "localhost")
	v.SetDefault("postgres.port", "5432")
	v.SetDefault("postgres.user", "wanrun")
	v.SetDefault("postgres.password", "__dummdy__")
	v.SetDefault("postgres.dbname", "dbname")
}

// 環境変数の取得
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

/*
DB情報のconfig構造体の取得
*/
func DbInfo() *DBInfoConfig {
	return &DBInfoConfig{
		postgresUser:     v.GetString("postgres.user"),
		postgresPassword: v.GetString("postgres.password"),
		postgresHost:     v.GetString("postgres.host"),
		postgresPort:     v.GetString("postgres.port"),
		postgresDB:       v.GetString("postgres.dbname"),
	}
}
func (c DBInfoConfig) PostgresUser() string {
	return c.postgresUser
}
func (c DBInfoConfig) PostgresPassword() string {
	return c.postgresPassword
}
func (c DBInfoConfig) PostgresHost() string {
	return c.postgresHost
}
func (c DBInfoConfig) PostgresPort() string {
	return c.postgresPort
}
func (c DBInfoConfig) PostgresDB() string {
	return c.postgresDB
}

// db情報 end

/*
loadしたviperからkeyで値を取得
*/
func FetchConfigStr(key string) string {
	return v.GetString(key)
}

/*
loadしたviperからkeyで値を取得(int)
*/
func FetchConfigInt(key string) int {
	return v.GetInt(key)
}

/*
loadしたviperからkeyで値を取得(bool)
*/
func FetchConfigBool(key string) bool {
	return v.GetBool(key)
}
