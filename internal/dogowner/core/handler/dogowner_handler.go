package handler

import (
	"github.com/labstack/echo/v4"
	authRepository "github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	authDTO "github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	authHandler "github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	dogOwnerRepository "github.com/wanrun-develop/wanrun/internal/dogowner/adapters/repository"
	doDTO "github.com/wanrun-develop/wanrun/internal/dogowner/core/dto"
	model "github.com/wanrun-develop/wanrun/internal/models"
	"github.com/wanrun-develop/wanrun/internal/transaction"
	wrErrors "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	wrUtil "github.com/wanrun-develop/wanrun/pkg/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type IDogOwnerHandler interface {
	DogOwnerSignUp(c echo.Context, doReq doDTO.DogOwnerReq) (authDTO.IssuedJwT, error)
}

type dogOwnerHandler struct {
	dosr dogOwnerRepository.IDogOwnerScopeRepository
	tm   transaction.ITransactionManager
	asr  authRepository.IAuthScopeRepository
	dor  dogOwnerRepository.IDogOwnerRepository
	ar   authRepository.IAuthRepository
}

func NewDogOwnerHandler(
	dosr dogOwnerRepository.IDogOwnerScopeRepository,
	tm transaction.ITransactionManager,
	asr authRepository.IAuthScopeRepository,
	dor dogOwnerRepository.IDogOwnerRepository,
	ar authRepository.IAuthRepository,
) IDogOwnerHandler {
	return &dogOwnerHandler{
		dosr: dosr,
		tm:   tm,
		asr:  asr,
		dor:  dor,
		ar:   ar,
	}
}

// DogOwnerSignUp: dogOwnerの登録し、検証済みのJWTを返す
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用されます。
//   - doDTO.DogOwnerReq: dogOwnerに対するリクエスト情報
//
// return:
//   - string
//   - error: error情報
func (doh *dogOwnerHandler) DogOwnerSignUp(c echo.Context, doReq doDTO.DogOwnerReq) (authDTO.IssuedJwT, error) {
	logger := log.GetLogger(c).Sugar()

	// パスワードのハッシュ化
	hash, err := bcrypt.GenerateFromPassword([]byte(doReq.Password), bcrypt.DefaultCost) // 一旦costをデフォルト値

	if err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードに不正な文字列が入っています。",
			wrErrors.NewDogOwnerClientErrorEType(),
		)
		logger.Error(wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// EmailとPhoneNumberのバリデーション
	if wrErr := validateEmailOrPhoneNumber(doReq); wrErr != nil {
		logger.Error(wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// JWT IDの生成
	jwtID, wrErr := authHandler.GenerateJwtID(c)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// requestからDogOwnerの構造体に詰め替え
	dogOwnerCredential := model.DogOwnerCredential{
		Email:       wrUtil.NewSqlNullString(doReq.Email),
		PhoneNumber: wrUtil.NewSqlNullString(doReq.PhoneNumber),
		Password:    wrUtil.NewSqlNullString(string(hash)),
		GrantType:   wrUtil.NewSqlNullString(model.PASSWORD_GRANT_TYPE), // Password認証
		AuthDogOwner: model.AuthDogOwner{
			JwtID: wrUtil.NewSqlNullString(jwtID),
			DogOwner: model.DogOwner{
				Name: wrUtil.NewSqlNullString(doReq.DogOwnerName),
			},
		},
	}

	logger.Debugf("dogOwnerCredential %v, Type: %T", dogOwnerCredential, dogOwnerCredential)

	ctx := c.Request().Context()

	// Emailの重複チェック
	if wrErr := doh.ar.CheckDuplicate(c, model.EmailField, dogOwnerCredential.Email); wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// PhoneNumberの重複チェック
	if wrErr := doh.ar.CheckDuplicate(c, model.PhoneNumberField, dogOwnerCredential.PhoneNumber); wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// dogOwnerの作成する1トランザクション
	if err := doh.tm.DoInTransaction(c, ctx, func(tx *gorm.DB) error {

		// DogOwnerを作成
		if wrErr := doh.dosr.CreateDogOwner(tx, c, &dogOwnerCredential); wrErr != nil {
			return wrErr
		}

		// AuthDogOwnerを作成
		if wrErr := doh.asr.CreateAuthDogOwner(tx, c, &dogOwnerCredential); wrErr != nil {
			return wrErr
		}

		// DogOwnerのCredentialを作成
		if wrErr := doh.asr.CreateDogOwnerCredential(tx, c, &dogOwnerCredential); wrErr != nil {
			return wrErr
		}

		// 正常に完了
		return nil

	}); err != nil {
		logger.Error("Transaction failed:", err)
		return authDTO.IssuedJwT{}, err
	}

	// 正常に終了
	logger.Infof("Successfully created SignUp DogOwner: %v", dogOwnerCredential)

	// 作成したDogOwnerの情報をdto詰め替え
	dogOwnerDetail := authDTO.JwtInfoDTO{
		AuthUserInfoDTO: authDTO.AuthUserInfoDTO{
			UserID: dogOwnerCredential.AuthDogOwner.DogOwnerID.Int64,
			RoleID: core.DOGOWNER_ROLE,
		},
		JwtID: dogOwnerCredential.AuthDogOwner.JwtID.String,
	}

	logger.Infof("dogOwnerDetail: %v", dogOwnerDetail)

	// 署名済みのjwt token取得
	token, refreshToken, wrErr := authHandler.GetSignedJwt(c, dogOwnerDetail)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	return authDTO.IssuedJwT{AccessToken: token, RefreshToken: refreshToken}, nil
}

// validateEmailOrPhoneNumber: EmailかPhoneNumberの識別バリデーション。パスワード認証は、EmailかPhoneNumberで登録するため
//
// args:
//   - dto.DogOwnerReq: DogOwnerのRequest
//
// return:
//   - error: err情報
func validateEmailOrPhoneNumber(doReq doDTO.DogOwnerReq) error {
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
