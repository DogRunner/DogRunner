package controller

import (

	// "github.com/golang-jwt/jwt/v5"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	"github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	"github.com/wanrun-develop/wanrun/internal/wrcontext"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
)

type IAuthController interface {
	// SignUp(c echo.Context) error
	LogInDogowner(echo.Context) error
	LogInDogrunmg(echo.Context) error
	RevokeDogowner(echo.Context) error
	RevokeDogrunmg(echo.Context) error
	// GoogleOAuth(echo.Context) error
	IssueGeneralUserToken(echo.Context) error
}

type authController struct {
	ah handler.IAuthHandler
}

func NewAuthController(ah handler.IAuthHandler) IAuthController {
	return &authController{ah}
}

/*
GoogleのOAuth認証
*/
// func (ac *authController) GoogleOAuth(c echo.Context) error {
// 	logger := log.GetLogger(c).Sugar()

// 	// GrantTypeヘッダーを取得
// 	grantTypeHeader := c.Request().Header.Get(string(types.OAUTH_IDENTIFICATION_HEADER))

// 	// GrantTypeヘッダーのバリデーション
// 	if err := dto.ValidateGrantTypeHeader(grantTypeHeader, string(types.OAUTH_GRANT_TYPE_HEADER)); err != nil {
// 		err = wrErrors.NewWRError(err, "ヘッダー情報が異なります。", wrErrors.NewDogrunClientErrorEType())
// 		logger.Error(err)
// 		return err
// 	}

// 	// GrantTypeに型変換
// 	grantType := types.GrantType(grantTypeHeader)
// 	logger.Infof("grantTypeHeader: %v", grantType)

// 	// 認証コードの取得
// 	authorizationCode := c.QueryParam("code")

// 	// ユーザーが承認しなかったら、エラーのクエリパラメータにくるため
// 	oauthErrorCode := c.QueryParam("error")

// 	logger.Infof("authorizationCode: %v, oauthErrorCode: %v", authorizationCode, oauthErrorCode)

// 	// クエリパラメータのバリデーション
// 	if err := dto.ValidateOAuthResCode(authorizationCode, oauthErrorCode); err != nil {
// 		err = wrErrors.NewWRError(err, "承認をしてください。", wrErrors.NewDogrunClientErrorEType())
// 		logger.Error(err)
// 		return err
// 	}

// 	// OAuth認証
// 	resDogOwner, wrErr := ac.ah.GoogleOAuth(c, authorizationCode, grantType)

// 	if wrErr != nil {
// 		return wrErr
// 	}

// 	// jwt処理
// 	return jwtProcessing(c, resDogOwner)
// }

// SignUp: Password認証
//
// args:
//   - echo.Context: c Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//
// return:
//   - error: error情報
// func (ac *authController) SignUp(c echo.Context) error {
// 	logger := log.GetLogger(c).Sugar()

// 	ador := dto.AuthDogOwnerReq{}

// 	if err := c.Bind(&ador); err != nil {
// 		wrErr := errors.NewWRError(err, "入力項目に不正があります。", errors.NewDogOwnerClientErrorEType())
// 		logger.Error(wrErr)
// 		return wrErr
// 	}

// 	// dogOwnerのSignUp
// 	dogOwnerDetail, wrErr := ac.ah.CreateDogOwner(c, ador)

// 	if wrErr != nil {
// 		return wrErr
// 	}

// 	// 署名済みのjwt token取得
// 	token, wrErr := ac.ah.GetSignedJwt(c, dogOwnerDetail)

// 	if wrErr != nil {
// 		return wrErr
// 	}

// 	return c.JSON(http.StatusCreated, map[string]string{
// 		"accessToken": token,
// 	})
// }

// LogInDogowner: dogownerのlogin機能
//
// args:
//   - echo.Context: c Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//
// return:
//   - error: error情報
func (ac *authController) LogInDogowner(c echo.Context) error {
	logger := log.GetLogger(c).Sugar()

	adoReq := dto.AuthDogOwnerReq{}

	if err := c.Bind(&adoReq); err != nil {
		wrErr := errors.NewWRError(
			err,
			"入力項目に不正があります。",
			errors.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return wrErr
	}

	// LogIn機能
	token, wrErr := ac.ah.LogInDogowner(c, adoReq)

	if wrErr != nil {
		return wrErr
	}

	return c.JSON(http.StatusOK, token)
}

// RevokeDogowner: dogownerのrevoke機能
//
// args:
//   - echo.Context: c Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//
// return:
//   - error: error情報
func (ac *authController) RevokeDogowner(c echo.Context) error {
	// claimsからdogrunmgのID取得
	dogownerID, wrErr := wrcontext.GetLoginUserID(c)

	if wrErr != nil {
		return wrErr
	}

	if wrErr := ac.ah.RevokeDogowner(c, dogownerID); wrErr != nil {
		return wrErr
	}

	return c.JSON(http.StatusOK, map[string]any{})
}

// LogInDogrunmg: Dogrunmgのlogin機能
//
// args:
//   - echo.Context: c Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//
// return:
//   - error: error情報
func (ac *authController) LogInDogrunmg(c echo.Context) error {
	logger := log.GetLogger(c).Sugar()

	admReq := dto.AuthDogrunmgReq{}

	if err := c.Bind(&admReq); err != nil {
		wrErr := errors.NewWRError(err, "入力項目に不正があります。", errors.NewAuthClientErrorEType())
		logger.Error(wrErr)
		return wrErr
	}

	// バリデータのインスタンス作成
	validate := validator.New()

	//リクエストボディのバリデーション
	if err := validate.Struct(&admReq); err != nil {
		err = errors.NewWRError(
			err,
			"必須の項目に不正があります。",
			errors.NewAuthClientErrorEType(),
		)
		logger.Error(err)
		return err
	}

	// dogrunmgのLogIn
	token, wrErr := ac.ah.LogInDogrunmg(c, admReq)

	if wrErr != nil {
		return wrErr
	}

	return c.JSON(http.StatusOK, token)
}

// RevokeDogrunmg: dogrunmgのrevoke機能
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//
// return:
//   - error: error情報
func (ac *authController) RevokeDogrunmg(c echo.Context) error {
	// claimsからdogrunmgのID取得
	dogrunmgID, wrErr := wrcontext.GetLoginUserID(c)

	if wrErr != nil {
		return wrErr
	}

	if wrErr := ac.ah.RevokeDogrunmg(c, dogrunmgID); wrErr != nil {
		return wrErr
	}

	return c.JSON(http.StatusOK, map[string]any{})
}

// /*
// OAuthのクエリパラメータのバリデーション
// */
// func ValidateOAuthResCode(authorizationCode string, oauthErrorCode string) error {
// 	// "error" パラメータがある場合はエラーレスポンスを返す
// 	if oauthErrorCode != "" {
// 		wrErr := wrErrors.NewWRError(
// 			errOAuthFailed,
// 			"認証に失敗しました。",
// 			wrErrors.NewDogOwnerClientErrorEType(),
// 		)
// 		return wrErr
// 	}

// 	// "code" パラメータがある場合はそのまま処理
// 	if authorizationCode != "" {
// 		return nil
// 	}

// 	// どちらのパラメータもない場合は不正なリクエストとしてエラーを返す
// 	return errOAuthInvalidReq
// }

// IssueGeneralUserToke: 一般ユーザーのjwt発行
//
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - error:	エラー
func (ac *authController) IssueGeneralUserToken(c echo.Context) error {

	token, wrErr := ac.ah.IssueGeneralUserToke(c)
	if wrErr != nil {
		return wrErr
	}
	return c.JSON(http.StatusOK, token)
}
