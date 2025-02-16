package middleware

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/configs"
	"github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	"github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	wrErrs "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	"golang.org/x/exp/slices"
)

type IAuthJwt interface {
	NewJwtValidationMiddleware() echo.MiddlewareFunc
}

type authJwt struct {
	ar repository.IAuthRepository
}

func NewAuthJwt(ar repository.IAuthRepository) IAuthJwt {
	return &authJwt{ar}
}

// スキップ対象のパスを定義
var skipPaths = []string{
	"/auth/dogowner/token",
	"/auth/dogrunmg/token",
	"/dogowner/signUp",
	"/org/contract",
	"/health",
	"/auth/general/token",
}

// NewJwtValidationMiddleware: JWT検証用のミドルウェア設定を生成
//
// args:
//   - string: スキップするルートパスのプレフィックス（例: "/auth" で auth グループ配下のルートをスキップ）
//
// return:
//   - echo.MiddlewareFunc: JWT検証のためのミドルウェア設定
func (aj *authJwt) NewJwtValidationMiddleware() echo.MiddlewareFunc {
	return echojwt.WithConfig(
		echojwt.Config{
			SigningKey: []byte(configs.FetchConfigStr("jwt.os.secret.key")), // 署名用の秘密鍵
			NewClaimsFunc: func(c echo.Context) jwt.Claims {
				return &handler.AccountClaims{} // カスタムクレームを設定
			},
			TokenLookup: core.TOKEN_LOOK_UP, // トークンの取得場所
			ContextKey:  core.CONTEXT_KEY,   // カスタムキーを設定
			Skipper: func(c echo.Context) bool { // スキップするパスを指定
				path := c.Request().URL.Path
				return slices.Contains(skipPaths, path)
			},
			SuccessHandler: func(c echo.Context) {
				// contextからJWTのclaims取得と検証, jwtIDの一致確認
				claims, wrErr := aj.extractAndValidateJwtClaims(c)

				if wrErr != nil {
					neRes := wrErrs.NewErrorRes(wrErr)
					_ = c.JSON(http.StatusUnauthorized, neRes)
					return
				}

				// 全ての検証を終えたclaimsをcontextにセット
				c.Set(core.CONTEXT_KEY, claims)
			},
			ErrorHandler: func(c echo.Context, err error) error { //エラーをラップ
				logger := log.GetLogger(c).Sugar()
				logger.Error(err)
				err = wrErrs.NewWRError(err, "authentication error", wrErrs.NewAuthClientErrorEType())
				return err
			},
		},
	)
}

// extractAndValidateJwtClaims: contextからJWTのclaimsを取得と検証とバリデーション
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//
// return:
//   - error: error情報
func (aj *authJwt) extractAndValidateJwtClaims(c echo.Context) (*handler.AccountClaims, error) {
	logger := log.GetLogger(c).Sugar()

	// JWTトークンをコンテキストから取得
	token, ok := c.Get(core.CONTEXT_KEY).(*jwt.Token)
	if !ok || token == nil {
		wrErr := wrErrs.NewWRError(
			nil,
			"JWTトークンが見つかりません。",
			wrErrs.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return nil, wrErr
	}

	// トークンが有効か確認
	if !token.Valid {
		wrErr := wrErrs.NewWRError(
			nil,
			"無効なJWTトークンです。",
			wrErrs.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return nil, wrErr
	}

	// クレーム情報を取得
	claims, ok := token.Claims.(*handler.AccountClaims)
	if !ok {
		wrErr := wrErrs.NewWRError(
			nil,
			"クレーム情報の取得に失敗しました。",
			wrErrs.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return nil, wrErr
	}

	// ExpiresAtの有効期限を確認
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		wrErr := wrErrs.NewWRError(
			nil,
			"JWTトークンの有効期限が切れています。",
			wrErrs.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return nil, wrErr
	}

	// リクエストのJWT内に含まれる`jwt_id`が、DBの`jwt_id`と一致するかを検証
	if wrErr := aj.jwtIDValid(c, claims); wrErr != nil {
		return nil, wrErr
	}

	return claims, nil
}

// JwtValid: リクエストのJWT内に含まれる`jwt_id`が、DBの`jwt_id`と一致するかを検証
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - *handler.AccountClaims: contextから取得したJWTのクレーム情報
//
// return:
//   - error: error情報
func (aj *authJwt) jwtIDValid(c echo.Context, ac *handler.AccountClaims) error {
	logger := log.GetLogger(c).Sugar()

	// Roleによる設定分岐
	getJwtID := func(role int, id int64) (string, error) {
		switch role {
		// dogowner
		case core.DOGOWNER_ROLE:
			// dogownerのjwtID取得
			return aj.ar.GetDogownerJwtID(c, id)
		// dogrunmg
		case core.DOGRUNMG_ROLE, core.DOGRUNMG_ADMIN_ROLE:
			// dogrunmgのjwtID取得
			return aj.ar.GetDogrunmgJwtID(c, id)
		//general
		case core.GENERAL:
			//jetIDの定数返す
			return core.GENERAL_USER_JWT_ID, nil
		default:
			return "", wrErrs.NewWRError(
				nil,
				"不明なユーザーRoleです。",
				wrErrs.NewUnexpectedErrorEType(),
			)
		}
	}

	// JWT IDの取得
	jwtID, wrErr := getJwtID(ac.Role, ac.UserID)

	if wrErr != nil {
		logger.Error(wrErr)
		return wrErr
	}

	// JTIの一致確認
	if jwtID != ac.ID {
		wrErr := wrErrs.NewWRError(
			nil,
			"jwt_idが一致しません。",
			wrErrs.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return wrErr
	}

	return nil
}
