package handler

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/configs"
	"github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	authDTO "github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	model "github.com/wanrun-develop/wanrun/internal/models"
	wrErrors "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	"github.com/wanrun-develop/wanrun/pkg/util"
	"golang.org/x/crypto/bcrypt"
)

type IAuthHandler interface {
	LogInDogowner(c echo.Context, ador authDTO.AuthDogOwnerReq) (authDTO.IssuedJwT, error)
	RevokeDogowner(c echo.Context, dogownerID int64) error
	LogInDogrunmg(c echo.Context, ador authDTO.AuthDogrunmgReq) (authDTO.IssuedJwT, error)
	RevokeDogrunmg(c echo.Context, dmID int64) error
	// GoogleOAuth(c echo.Context, authorizationCode string, grantType types.GrantType) (dto.ResDogOwnerDto, error)
	IssueGeneralUserToke(c echo.Context) (authDTO.IssuedJwT, error)
}

type authHandler struct {
	ar repository.IAuthRepository
	// ag google.IOAuthGoogle
}

//	func NewAuthHandler(ar repository.IAuthRepository, g google.IOAuthGoogle) IAuthHandler {
//		return &authHandler{ar, g}
//	}
func NewAuthHandler(ar repository.IAuthRepository) IAuthHandler {
	return &authHandler{ar}
}

// JWTのClaims
type AccountClaims struct {
	UserID int64 `json:"userId"`
	Role   int   `json:"role"`
	jwt.RegisteredClaims
}

// LogInDogowner: dogownerの存在チェックバリデーションとJWTの更新, 署名済みjwtを返す
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - dto.AuthDogOwnerReq: authDogOwnerのリクエスト情報
//
// return:
//   - authDTO.IssuedJwT: 発行済みのjwt
//   - error: error情報
func (ah *authHandler) LogInDogowner(c echo.Context, adoReq authDTO.AuthDogOwnerReq) (authDTO.IssuedJwT, error) {
	logger := log.GetLogger(c).Sugar()

	ado := model.AuthDogOwner{}
	var err error

	if adoReq.AuthenticationType == core.PASSWORD {
		//リクエスト検証
		ado, err = ah.VerifyRequestAndFetchAuthDogOwnerPassword(c, adoReq)
		if err != nil {
			return authDTO.IssuedJwT{}, err
		}
	} else if adoReq.AuthenticationType == core.REFRESH {
		if adoReq.RefreshToken == "" {
			wrErr := wrErrors.NewWRError(
				nil,
				"認証トークンの再発行にはリフレッシュトークンが必要です。",
				wrErrors.NewAuthClientErrorEType())
			logger.Errorf("refresh token is required: %v", wrErr)
			return authDTO.IssuedJwT{}, wrErr
		}
		//リクエスト検証
		ado, err = ah.VerifyRequestAndFetchAuthDogOwnerRefresh(c, adoReq.RefreshToken)
		if err != nil {
			return authDTO.IssuedJwT{}, err
		}
	} else {
		wrErr := wrErrors.NewWRError(
			nil,
			"適切な認証方法'AuthenticationType'が指定されていません",
			wrErrors.NewAuthClientErrorEType())
		logger.Errorf("AuthenticationType is invalid: %v", wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// 認証トークンのJWT IDの生成
	jwtID, wrErr := GenerateJwtID(c)
	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}
	logger.Infoln("jwt_id", jwtID)

	// リフレッシュトークンのJWT IDの生成
	refreshJwtID, wrErr := GenerateJwtID(c)
	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}
	logger.Infoln("refresh_jwt_id", refreshJwtID)

	// 取得したdogownerのjtw_idの更新
	if wrErr := ah.ar.UpdateDogownerJwtID(c, ado.DogOwnerID.Int64, jwtID, refreshJwtID); wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// 作成したDogownerの情報をdto詰め替え
	jiDTO := authDTO.JwtInfoDTO{
		AuthUserInfoDTO: authDTO.AuthUserInfoDTO{
			UserID: ado.DogOwnerID.Int64,
			RoleID: core.DOGOWNER_ROLE,
		},
		JwtID:        jwtID,
		RefreshJwtID: refreshJwtID,
	}
	logger.Infof("dogownerDetail: %v", jiDTO)

	// 署名済みのjwt token取得
	token, refreshToken, wrErr := GetSignedJwt(c, jiDTO)
	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	return authDTO.IssuedJwT{AccessToken: token, RefreshToken: refreshToken}, nil
}

// VerifyRequestAndFetchAuthDogOwnerPassword	: パスワード認証時のユーザー認証のリクエスト検証とユーザー取得
// メールアドレスか電話番号のチェック
// auth_dog_owner系へ取得とチェック
//
// args:
//   - echo.Context:	コンテキスト
//   - authDTO.AuthDogOwnerReq:	リクエストボディ
//
// return:
//   - model.AuthDogOwner:	認証ユーザー
//   - error:	エラー
func (ah *authHandler) VerifyRequestAndFetchAuthDogOwnerPassword(c echo.Context, adoReq authDTO.AuthDogOwnerReq) (model.AuthDogOwner, error) {
	logger := log.GetLogger(c).Sugar()
	// EmailとPhoneNumberのバリデーション
	if wrErr := validateEmailOrPhoneNumber(adoReq); wrErr != nil {
		logger.Error(wrErr)
		return model.AuthDogOwner{}, wrErr
	}
	logger.Debugf("authDogownerReq: %v, Type: %T", adoReq, adoReq)

	// EmailかPhoneNumberから対象のDogowner情報の取得
	results, wrErr := ah.ar.GetDogOwnerByCredentials(c, adoReq)
	if wrErr != nil {
		return model.AuthDogOwner{}, wrErr
	}

	// 対象のdogownerがいない場合
	if len(results) == 0 {
		wrErr := wrErrors.NewWRError(
			nil,
			"対象のユーザーが存在しません",
			wrErrors.NewAuthClientErrorEType(),
		)
		logger.Errorf("Dogowner not found: %v", wrErr)
		return model.AuthDogOwner{}, wrErr
	}
	// 対象のdogownerが複数いるため、データの不整合が起きている(基本的に起きない)
	if len(results) > 1 {
		wrErr := wrErrors.NewWRError(
			nil,
			"データの不整合が起きています",
			wrErrors.NewAuthServerErrorEType(),
		)
		logger.Errorf("Multiple records found: %v", wrErr)
		return model.AuthDogOwner{}, wrErr
	}

	// パスワードの確認
	if err := bcrypt.CompareHashAndPassword([]byte(results[0].Password.String), []byte(adoReq.Password)); err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードが間違っています",
			wrErrors.NewAuthServerErrorEType())
		logger.Errorf("Password compare failure: %v", wrErr)
		return model.AuthDogOwner{}, wrErr
	}

	return results[0].AuthDogOwner, nil
}

// VerifyRequestAndFetchAuthDogOwnerRefresh:
//
// args:
//   - echo.Context:	コンテキスト
//   - string:	リフレッシュトークン
//
// return:
//   - model.AuthDogOwner:	認証ユーザー
//   - error:	エラー
func (ah *authHandler) VerifyRequestAndFetchAuthDogOwnerRefresh(c echo.Context, refreshToken string) (model.AuthDogOwner, error) {
	logger := log.GetLogger(c).Sugar()

	claims := &AccountClaims{}

	// 署名キーを指定
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		// 署名アルゴリズムが適切かチェック
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := wrErrors.NewWRError(nil, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]), wrErrors.NewAuthServerErrorEType())
			logger.Error(err)
			return nil, err
		}
		return []byte(configs.FetchConfigStr("jwt.os.secret.key")), nil
	})
	if err != nil {
		err := wrErrors.NewWRError(err, "リフレッシュトークンの著名検証に失敗しました。", wrErrors.NewAuthServerErrorEType())
		return model.AuthDogOwner{}, err
	}

	// クレームを取得
	refreshClaim, ok := token.Claims.(*AccountClaims)
	if !ok || !token.Valid {
		err = wrErrors.NewWRError(nil, "リフレッシュトークンは不正です。", wrErrors.NewAuthServerErrorEType())
		logger.Error(err)
		return model.AuthDogOwner{}, err
	}

	//jtiの検証
	ado, err := ah.ar.GetAuthDogOwnerByID(c, refreshClaim.UserID)
	if err != nil {
		return model.AuthDogOwner{}, err
	}
	if ado.RefreshJwtID.String != refreshClaim.ID {
		err = wrErrors.NewWRError(nil, "リフレッシュトークンは有効でないか、すでに失効済みです。", wrErrors.NewAuthServerErrorEType())
		logger.Error(err)
		return model.AuthDogOwner{}, err
	}
	return ado, nil
}

// RevokeDogowner: dogownerのRevoke機能
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: dogownerのID
//
// return:
//   - error: error情報
func (ah *authHandler) RevokeDogowner(c echo.Context, doID int64) error {
	// 対象のdogownerのIDからJWT IDの削除
	if wrErr := ah.ar.DeleteDogownerJwtID(c, doID); wrErr != nil {
		return wrErr
	}

	return nil
}

// LogInDogrunmg: dogrunmgの存在チェックバリデーションとJWTの更新, 署名済みjwtを返す
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - dto.AuthDogrunmgReq: authDogrunmgのリクエスト情報
//
// return:
//   - string: 検証済みのjwt
//   - error: error情報
func (ah *authHandler) LogInDogrunmg(c echo.Context, admReq authDTO.AuthDogrunmgReq) (authDTO.IssuedJwT, error) {
	logger := log.GetLogger(c).Sugar()

	logger.Debugf("authDogrunmgReq: %v, Type: %T", admReq, admReq)

	// Email情報を元にdogrunmgのクレデンシャル情報の取得
	results, err := ah.ar.GetDogrunmgByCredentials(c, admReq.Email)

	if err != nil {
		return authDTO.IssuedJwT{}, err
	}

	// 対象のdogrunmgがいない場合
	if len(results) == 0 {
		wrErr := wrErrors.NewWRError(
			nil,
			"対象のユーザーが存在しません",
			wrErrors.NewAuthClientErrorEType(),
		)
		logger.Errorf("Dogrunmg not found: %v", wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// 対象のdogrunmgが複数いるため、データの不整合が起きている(emailをuniqueにしているため基本的に起きない)
	if len(results) > 1 {
		wrErr := wrErrors.NewWRError(
			nil,
			"データの不整合が起きています",
			wrErrors.NewAuthServerErrorEType(),
		)
		logger.Errorf("Multiple records found for email (expected unique): %v", wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// パスワードの確認
	if err = bcrypt.CompareHashAndPassword([]byte(results[0].Password.String), []byte(admReq.Password)); err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードが間違っています",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Password compare failure: %v", wrErr)

		return authDTO.IssuedJwT{}, wrErr
	}

	// 更新用のJWT IDの生成
	jwtID, wrErr := GenerateJwtID(c)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// 取得したdogrunmgのjwt_idの更新
	if wrErr = ah.ar.UpdateDogrunmgJwtID(c, results[0].AuthDogrunmg.Dogrunmg.DogrunmgID.Int64, jwtID); wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// dogrunmgがadminかどうかの識別
	var roleID int
	if results[0].AuthDogrunmg.IsAdmin.Valid && results[0].AuthDogrunmg.IsAdmin.Bool {
		roleID = core.DOGRUNMG_ADMIN_ROLE
	} else {
		roleID = core.DOGRUNMG_ROLE
	}

	// 取得したDogrunmgの情報をdto詰め替え
	dogrunmgDetail := authDTO.JwtInfoDTO{
		AuthUserInfoDTO: authDTO.AuthUserInfoDTO{
			UserID: results[0].AuthDogrunmg.DogrunmgID.Int64,
			RoleID: roleID,
		},
		JwtID: jwtID,
	}

	logger.Infof("dogrunmgDetail: %v", dogrunmgDetail)

	// 署名済みのjwt token取得
	token, refreshToken, wrErr := GetSignedJwt(c, dogrunmgDetail)
	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	return authDTO.IssuedJwT{AccessToken: token, RefreshToken: refreshToken}, nil
}

// RevokeDogrunmg: dogrunmgのRevoke機能
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: dogrunmgのID
//
// return:
//   - error: error情報
func (ah *authHandler) RevokeDogrunmg(c echo.Context, dmID int64) error {
	// 対象のdogrunmgのIDからJWT IDの削除
	if wrErr := ah.ar.DeleteDogrunmgJwtID(c, dmID); wrErr != nil {
		return wrErr
	}

	return nil
}

/*
Google OAuth認証
*/
// func (ah *authHandler) GoogleOAuth(c echo.Context, authorizationCode string, grantType types.GrantType) (dto.ResDogOwnerDto, error) {
// 	logger := log.GetLogger(c).Sugar()

// 	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second) // 5秒で設定
// 	defer cancel()

// 	// 各token情報の取得
// 	token, wrErr := ah.ag.GetAccessToken(c, authorizationCode, ctx)

// 	if wrErr != nil {
// 		return dto.ResDogOwnerDto{}, wrErr
// 	}

// 	// トークン元にGoogleユーザー情報の取得
// 	googleUserInfo, wrErr := ah.ag.GetGoogleUserInfo(c, token, ctx)

// 	if wrErr != nil {
// 		return dto.ResDogOwnerDto{}, wrErr
// 	}

// 	// Googleユーザー情報の確認処理
// 	if googleUserInfo == nil {
// 		wrErr := wrErrors.NewWRError(
// 			errors.New(""),
// 			"no google user information",
// 			wrErrors.NewAuthServerErrorEType(),
// 		)
// 		logger.Errorf("No google user information error: %v", wrErr)
// 		return dto.ResDogOwnerDto{}, wrErr
// 	}

// 	// ドッグオーナーのcredentialの設定と型変換
// 	dogOwnerCredential := model.DogOwnerCredential{
// 		ProviderUserID: wrUtil.NewSqlNullString(googleUserInfo.UserId),
// 		Email:          wrUtil.NewSqlNullString(googleUserInfo.Email),
// 		AuthDogOwner: model.AuthDogOwner{
// 			AccessToken:           wrUtil.NewSqlNullString(token.AccessToken),
// 			RefreshToken:          wrUtil.NewSqlNullString(token.RefreshToken),
// 			AccessTokenExpiration: wrUtil.NewCustomTime(token.Expiry),
// 			GrantType:             grantType,
// 			DogOwner: model.DogOwner{
// 				Name: wrUtil.NewSqlNullString(googleUserInfo.Email),
// 			},
// 		},
// 	}

// 	// ドッグオーナーの作成
// 	dogOC, wrErr := ah.ar.CreateOAuthDogOwner(c, &dogOwnerCredential)

// 	if wrErr != nil {
// 		return dto.ResDogOwnerDto{}, wrErr
// 	}

// 	resDogOwner := dto.ResDogOwnerDto{
// 		DogOwnerID: dogOC.AuthDogOwner.DogOwner.DogOwnerID.Int64,
// 	}

// 	return resDogOwner, nil
// }

// GetSignedJwt: 署名済みのJWT tokenの取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - authDTO.JwtInfoDTO: jwtで使用する情報
//
// return:
//   - string: 署名した認証トークン
//   - string: 署名したリフレッシュトークン
//   - error: error情報
func GetSignedJwt(c echo.Context, jiDTO authDTO.JwtInfoDTO) (string, string, error) {
	// 秘密鍵取得
	secretKey := configs.FetchConfigStr("jwt.os.secret.key")
	jwtExpTime := configs.FetchConfigInt("jwt.exp.time")

	// jwt 認証トークン生成
	signedToken, wrErr := createToken(c, secretKey, jiDTO.AuthUserInfoDTO, jiDTO.JwtID, jwtExpTime)
	if wrErr != nil {
		return "", "", wrErr
	}

	if jiDTO.RefreshJwtID == "" {
		return signedToken, "", nil
	}

	RefreshJwtExpTime := configs.FetchConfigInt("refresh.jwt.exp.time")
	// jwt リフレッシュトークン生成
	signedRefreshToken, wrErr := createToken(c, secretKey, jiDTO.AuthUserInfoDTO, jiDTO.RefreshJwtID, RefreshJwtExpTime)
	if wrErr != nil {
		return "", "", wrErr
	}

	return signedToken, signedRefreshToken, nil
}

// createToken: 指定された秘密鍵を使用して認証用のJWTトークンを生成
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - string: secretKey   トークンの署名に使用する秘密鍵を表す文字列
//   - authDTO.UserAuthInfoDTO: jwtで使用する情報
//   - jwtID:	jwt_id値
//   - int: expTime トークンの有効期限を秒単位で指定. 0なら無期限とする
//
// return:
//   - string: 生成されたJWTトークンを表す文字列
//   - error: トークンの生成中に問題が発生したエラー
func createToken(
	c echo.Context,
	secretKey string,
	uaDTO authDTO.AuthUserInfoDTO,
	jwtID string,
	expTime int,
) (string, error) {
	logger := log.GetLogger(c).Sugar()

	var expiresNumericDate *jwt.NumericDate
	//0の場合は無期限トークンの発行
	if expTime != 0 {
		expiresNumericDate = jwt.NewNumericDate( // 有効時間
			time.Now().Add(
				time.Hour * time.Duration(expTime),
			),
		)
	}

	// JWTのペイロード
	claims := AccountClaims{
		UserID: uaDTO.UserID, // stringにコンバート
		Role:   uaDTO.RoleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expiresNumericDate, // 有効時間
			ID:        jwtID,
		},
	}
	// token生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// tokenに署名
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードに不正な文字列が入っています。",
			wrErrors.NewAuthClientErrorEType(),
		)
		logger.Error(wrErr)
		return "", err
	}

	return signedToken, nil
}

// GenerateJwtID: JwtIDの生成。引数の数だけランダムの文字列を生成
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//
// return:
//   - string: JwtID
//   - error: error情報
func GenerateJwtID(c echo.Context) (string, error) {
	logger := log.GetLogger(c).Sugar()

	// カスタムエラー処理
	handleError := func(err error) error {
		wrErr := wrErrors.NewWRError(
			err,
			"JwtID生成に失敗しました",
			wrErrors.NewAuthServerErrorEType(),
		)
		logger.Error(wrErr)
		return wrErr
	}

	// UUIDを生成
	return util.UUIDGenerator(handleError)
}

// validateEmailOrPhoneNumber: EmailかPhoneNumberの識別バリデーション。パスワード認証は、EmailかPhoneNumberで登録するため
//
// args:
//   - dto.DogOwnerReq: DogOwnerのRequest
//
// return:
//   - error: err情報
func validateEmailOrPhoneNumber(doReq authDTO.AuthDogOwnerReq) error {
	// 両方が空の場合はエラー
	if doReq.Email == "" && doReq.PhoneNumber == "" {
		wrErr := wrErrors.NewWRError(
			nil,
			"Emailと電話番号のどちらも空です",
			wrErrors.NewDogOwnerClientErrorEType(),
		)
		return wrErr
	}

	// 両方に値が入っている場合もエラー
	if doReq.Email != "" && doReq.PhoneNumber != "" {
		wrErr := wrErrors.NewWRError(
			nil,
			"Emailと電話番号のどちらも値が入っています",
			wrErrors.NewDogOwnerClientErrorEType(),
		)
		return wrErr
	}

	// どちらか片方だけが入力されている場合は正常
	return nil
}

// IssueGeneralUserToke: 一般ユーザーのjwr発行処理
//
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - string:	jwt
//   - error:	エラー
func (ah *authHandler) IssueGeneralUserToke(c echo.Context) (authDTO.IssuedJwT, error) {
	logger := log.GetLogger(c).Sugar()
	logger.Info("一般ユーザートークンの発行")

	auiDTO := authDTO.AuthUserInfoDTO{
		UserID: core.GENERAL_USER_ID,
		RoleID: core.GENERAL,
	}

	// 秘密鍵取得
	secretKey := configs.FetchConfigStr("jwt.os.secret.key")

	// jwt token生成(無期限)
	signedToken, wrErr := createToken(c, secretKey, auiDTO, core.GENERAL_USER_JWT_ID, 0)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	return authDTO.IssuedJwT{AccessToken: signedToken}, wrErr
}
