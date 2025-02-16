package wrcontext

import (
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	"github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
)

// GetClaims : contextから検証済みのclaims情報を取得する共通関数
//
// args:
//   - echo.MiddlewareFunc: JWT検証のためのミドルウェア設定
//
// return:
//   - *AccountClaims: 検証済みのclaims情報
func GetVerifiedClaims(c echo.Context) (*handler.AccountClaims, error) {
	logger := log.GetLogger(c).Sugar()

	claims, ok := c.Get(core.CONTEXT_KEY).(*handler.AccountClaims)
	if !ok || claims == nil {
		wrErr := errors.NewWRError(
			nil,
			"クレーム情報が見つかりません。",
			errors.NewDogOwnerClientErrorEType(),
		)
		logger.Error(wrErr)
		return nil, wrErr
	}

	return claims, nil
}

// GetLoginUserId: ログインユーザーIDの取得
//
//	コンテキストのjwt解析済みclaimからユーザーID取得
//
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - int64:	ユーザーID
func GetLoginUserID(c echo.Context) (int64, error) {
	claims, err := GetVerifiedClaims(c)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

// GetLoginUserId: ログインユーザーのdogownerIDの取得
// コンテキストのjwt解析済みclaimからユーザーID取得
// dogownerのみ許容
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - int64:	ユーザーID
func GetLoginDogownerID(c echo.Context) (int64, error) {
	claims, err := GetVerifiedClaims(c)
	if err != nil {
		return 0, err
	}
	if claims.Role != core.DOGOWNER_ROLE {
		err = errors.NewWRError(
			nil,
			"このログインユーザーはdogownerではありません。",
			errors.NewAuthClientErrorEType(),
		)
		return 0, err
	}
	return claims.UserID, nil
}

// GetLoginUserRole: ログインユーザー（認証済み）のロールを取得する
//
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - int:	ロールID
//   - error:	エラー
func GetLoginUserRole(c echo.Context) (int, error) {
	claims, err := GetVerifiedClaims(c)
	if err != nil {
		return 0, err
	}
	return claims.Role, nil
}
