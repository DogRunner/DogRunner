package handler

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/configs"
	"github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	authDTO "github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	wrErrors "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	"github.com/wanrun-develop/wanrun/pkg/util"
	"golang.org/x/crypto/bcrypt"
)

type IAuthHandler interface {
	LogInDogowner(c echo.Context, ador authDTO.AuthDogOwnerReq) (string, error)
	RevokeDogowner(c echo.Context, dogownerID int64) error
	LogInDogrunmg(c echo.Context, ador authDTO.AuthDogrunmgReq) (string, error)
	RevokeDogrunmg(c echo.Context, dmID int64) error
	// GoogleOAuth(c echo.Context, authorizationCode string, grantType types.GrantType) (dto.ResDogOwnerDto, error)
	IssueGeneralUserToke(c echo.Context) (string, error)
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
	UserID string `json:"userId"`
	Role   int    `json:"role"`
	jwt.RegisteredClaims
}

// GetDogOwnerIDAsInt64: 共通処理で、int64のDogOwnerのID取得。
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//
// return:
//   - int64: dogOwnerのID情報(int64)
//   - error: error情報
func (claims *AccountClaims) GetDogOwnerIDAsInt64(c echo.Context) (int64, error) {
	logger := log.GetLogger(c).Sugar()

	// IDをstringからint64に変換
	dogOwnerID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		wrErr := errors.NewWRError(
			nil,
			"認証情報が違います。",
			errors.NewDogOwnerClientErrorEType(),
		)
		logger.Error(wrErr)
		return 0, err
	}
	return dogOwnerID, nil
}

// LogInDogowner: dogownerの存在チェックバリデーションとJWTの更新, 署名済みjwtを返す
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - dto.AuthDogOwnerReq: authDogOwnerのリクエスト情報
//
// return:
//   - string: 検証済みのjwt
//   - error: error情報
func (ah *authHandler) LogInDogowner(c echo.Context, adoReq authDTO.AuthDogOwnerReq) (string, error) {
	logger := log.GetLogger(c).Sugar()

	// EmailとPhoneNumberのバリデーション
	if wrErr := validateEmailOrPhoneNumber(adoReq); wrErr != nil {
		logger.Error(wrErr)
		return "", wrErr
	}

	logger.Debugf("authDogownerReq: %v, Type: %T", adoReq, adoReq)

	// EmailかPhoneNumberから対象のDogowner情報の取得
	results, wrErr := ah.ar.GetDogOwnerByCredentials(c, adoReq)

	if wrErr != nil {
		return "", wrErr
	}

	// 対象のdogownerがいない場合
	if len(results) == 0 {
		wrErr := wrErrors.NewWRError(
			nil,
			"対象のユーザーが存在しません",
			wrErrors.NewAuthClientErrorEType(),
		)
		logger.Errorf("Dogowner not found: %v", wrErr)
		return "", wrErr
	}

	// 対象のdogownerが複数いるため、データの不整合が起きている(基本的に起きない)
	if len(results) > 1 {
		wrErr := wrErrors.NewWRError(
			nil,
			"データの不整合が起きています",
			wrErrors.NewAuthServerErrorEType(),
		)
		logger.Errorf("Multiple records found: %v", wrErr)
		return "", wrErr
	}

	// パスワードの確認
	if err := bcrypt.CompareHashAndPassword([]byte(results[0].Password.String), []byte(adoReq.Password)); err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードが間違っています",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Password compare failure: %v", wrErr)

		return "", wrErr
	}

	// 更新用のJWT IDの生成
	jwtID, wrErr := GenerateJwtID(c)

	if wrErr != nil {
		return "", wrErr
	}

	// 取得したdogownerのjtw_idの更新
	if wrErr := ah.ar.UpdateDogownerJwtID(c, results[0].AuthDogOwner.DogOwner.DogOwnerID.Int64, jwtID); wrErr != nil {
		return "", wrErr
	}

	// 作成したDogownerの情報をdto詰め替え
	dogownerDetail := authDTO.UserAuthInfoDTO{
		UserID: results[0].AuthDogOwner.DogOwnerID.Int64,
		JwtID:  jwtID,
		RoleID: core.DOGOWNER_ROLE,
	}

	logger.Infof("dogownerDetail: %v", dogownerDetail)

	// 署名済みのjwt token取得
	token, wrErr := GetSignedJwt(c, dogownerDetail)

	if wrErr != nil {
		return "", wrErr
	}

	return token, nil
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
func (ah *authHandler) LogInDogrunmg(c echo.Context, admReq authDTO.AuthDogrunmgReq) (string, error) {
	logger := log.GetLogger(c).Sugar()

	logger.Debugf("authDogrunmgReq: %v, Type: %T", admReq, admReq)

	// Email情報を元にdogrunmgのクレデンシャル情報の取得
	results, err := ah.ar.GetDogrunmgByCredentials(c, admReq.Email)

	if err != nil {
		return "", err
	}

	// 対象のdogrunmgがいない場合
	if len(results) == 0 {
		wrErr := wrErrors.NewWRError(
			nil,
			"対象のユーザーが存在しません",
			wrErrors.NewAuthClientErrorEType(),
		)
		logger.Errorf("Dogrunmg not found: %v", wrErr)
		return "", wrErr
	}

	// 対象のdogrunmgが複数いるため、データの不整合が起きている(emailをuniqueにしているため基本的に起きない)
	if len(results) > 1 {
		wrErr := wrErrors.NewWRError(
			nil,
			"データの不整合が起きています",
			wrErrors.NewAuthServerErrorEType(),
		)
		logger.Errorf("Multiple records found for email (expected unique): %v", wrErr)
		return "", wrErr
	}

	// パスワードの確認
	if err = bcrypt.CompareHashAndPassword([]byte(results[0].Password.String), []byte(admReq.Password)); err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードが間違っています",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Password compare failure: %v", wrErr)

		return "", wrErr
	}

	// 更新用のJWT IDの生成
	jwtID, wrErr := GenerateJwtID(c)

	if wrErr != nil {
		return "", wrErr
	}

	// 取得したdogrunmgのjwt_idの更新
	if wrErr = ah.ar.UpdateDogrunmgJwtID(c, results[0].AuthDogrunmg.Dogrunmg.DogrunmgID.Int64, jwtID); wrErr != nil {
		return "", wrErr
	}

	// dogrunmgがadminかどうかの識別
	var roleID int
	if results[0].AuthDogrunmg.IsAdmin.Valid && results[0].AuthDogrunmg.IsAdmin.Bool {
		roleID = core.DOGRUNMG_ADMIN_ROLE
	} else {
		roleID = core.DOGRUNMG_ROLE
	}

	// 取得したDogrunmgの情報をdto詰め替え
	dogrunmgDetail := authDTO.UserAuthInfoDTO{
		UserID: results[0].AuthDogrunmg.DogrunmgID.Int64,
		JwtID:  jwtID,
		RoleID: roleID,
	}

	logger.Infof("dogrunmgDetail: %v", dogrunmgDetail)

	// 署名済みのjwt token取得
	token, wrErr := GetSignedJwt(c, dogrunmgDetail)

	if wrErr != nil {
		return "", wrErr
	}

	return token, nil
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
//   - authDTO.UserAuthInfoDTO: jwtで使用する情報
//
// return:
//   - string: 署名したtoken
//   - error: error情報
func GetSignedJwt(c echo.Context, uaDTO authDTO.UserAuthInfoDTO) (string, error) {
	// 秘密鍵取得
	secretKey := configs.FetchConfigStr("jwt.os.secret.key")
	jwtExpTime := configs.FetchConfigInt("jwt.exp.time")

	// jwt token生成
	signedToken, wrErr := createToken(c, secretKey, uaDTO, jwtExpTime)

	if wrErr != nil {
		return "", wrErr
	}

	return signedToken, wrErr
}

// createToken: 指定された秘密鍵を使用して認証用のJWTトークンを生成
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - string: secretKey   トークンの署名に使用する秘密鍵を表す文字列
//   - authDTO.UserAuthInfoDTO: jwtで使用する情報
//   - int: expTime トークンの有効期限を秒単位で指定. 0なら無期限とする
//
// return:
//   - string: 生成されたJWTトークンを表す文字列
//   - error: トークンの生成中に問題が発生したエラー
func createToken(
	c echo.Context,
	secretKey string,
	uaDTO authDTO.UserAuthInfoDTO,
	expTime int,
) (string, error) {
	logger := log.GetLogger(c).Sugar()

	var expireNumericDate *jwt.NumericDate
	//0の場合は無期限トークンの発行
	if expTime != 0 {
		expireNumericDate = jwt.NewNumericDate( // 有効時間
			time.Now().Add(
				time.Hour * time.Duration(expTime),
			),
		)
	}

	// JWTのペイロード
	claims := AccountClaims{
		UserID: strconv.FormatInt(uaDTO.UserID, 10), // stringにコンバート
		Role:   uaDTO.RoleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expireNumericDate, // 有効時間
			ID:        uaDTO.JwtID,
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
func (ah *authHandler) IssueGeneralUserToke(c echo.Context) (string, error) {
	logger := log.GetLogger(c).Sugar()
	logger.Info("一般ユーザートークンの発行")

	userInfoDTO := authDTO.UserAuthInfoDTO{
		UserID: core.GENERAL_USER_ID,
		JwtID:  core.GENERAL_USER_JWT_ID,
		RoleID: core.GENERAL,
	}

	// 秘密鍵取得
	secretKey := configs.FetchConfigStr("jwt.os.secret.key")

	// jwt token生成(無期限)
	signedToken, wrErr := createToken(c, secretKey, userInfoDTO, 0)

	if wrErr != nil {
		return "", wrErr
	}

	return signedToken, wrErr
}
