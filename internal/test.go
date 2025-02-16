package internal

import (
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
)

func Test(c echo.Context) error {
	logger := log.GetLogger(c).Sugar()
	logger.Info("Test*()の実行. ")

	logger.Info("Default Time Zone:", time.Local)
	logger.Info(time.Now())
	return nil
}

func testError() error {
	file := "xxx/xxx"
	_, err := os.Open(file)
	if err != nil {
		err := errors.NewWRError(err, "エラー発生: entityFuncのファイル読み込み", errors.NewAuthClientErrorEType())
		return err
	}
	return nil
}
