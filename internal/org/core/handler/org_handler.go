package handler

import (
	"github.com/labstack/echo/v4"
	authRepository "github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	authDTO "github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	authFacade "github.com/wanrun-develop/wanrun/internal/auth/core/facade"
	authHandler "github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	dogrunmgRepository "github.com/wanrun-develop/wanrun/internal/dogrunmg/adapters/repository"
	model "github.com/wanrun-develop/wanrun/internal/models"
	orgRepository "github.com/wanrun-develop/wanrun/internal/org/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/org/core/dto"
	"github.com/wanrun-develop/wanrun/internal/transaction"
	wrErrors "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	wrUtil "github.com/wanrun-develop/wanrun/pkg/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type IOrgHandler interface {
	OrgSignUp(c echo.Context, orgReq dto.OrgReq) (authDTO.IssuedJwT, error)
}

type orgHandler struct {
	osr  orgRepository.IOrgScopeRepository
	tm   transaction.ITransactionManager
	dmsr dogrunmgRepository.IDogrunmgScopeRepository
	asr  authRepository.IAuthScopeRepository
	af   authFacade.IAuthFacade
}

func NewOrgHandler(
	osr orgRepository.IOrgScopeRepository,
	tm transaction.ITransactionManager,
	dmsr dogrunmgRepository.IDogrunmgScopeRepository,
	asr authRepository.IAuthScopeRepository,
	af authFacade.IAuthFacade,
) IOrgHandler {
	return &orgHandler{
		osr:  osr,
		tm:   tm,
		dmsr: dmsr,
		asr:  asr,
		af:   af,
	}
}

func (oh *orgHandler) OrgSignUp(
	c echo.Context,
	orgReq dto.OrgReq,
) (authDTO.IssuedJwT, error) {
	logger := log.GetLogger(c).Sugar()

	// パスワードのハッシュ化
	hash, err := bcrypt.GenerateFromPassword([]byte(orgReq.Password), bcrypt.DefaultCost) // 一旦costをデフォルト値

	if err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"パスワードに不正な文字列が入っています。",
			wrErrors.NewOrgClientErrorEType(),
		)
		logger.Error(wrErr)
		return authDTO.IssuedJwT{}, wrErr
	}

	// JWT IDの生成
	jwtID, wrErr := authHandler.GenerateJwtID(c)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// orgのEmailバリデーション
	if wrErr := oh.af.OrgEmailValidate(c, orgReq.ContactEmail); wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	// requestからorgの構造体に詰め替え
	orgInfo := model.DogrunmgCredential{
		Email:    wrUtil.NewSqlNullString(orgReq.ContactEmail),
		Password: wrUtil.NewSqlNullString(string(hash)),
		AuthDogrunmg: model.AuthDogrunmg{
			JwtID:   wrUtil.NewSqlNullString(jwtID),
			IsAdmin: wrUtil.NewSqlNullBool(true), // 初期adminユーザーのため
			Dogrunmg: model.Dogrunmg{
				Name: wrUtil.NewSqlNullString("admin"),
				Organization: model.Organization{
					Name:         wrUtil.NewSqlNullString(orgReq.OrgName),
					ContactEmail: wrUtil.NewSqlNullString(orgReq.ContactEmail),
					PhoneNumber:  wrUtil.NewSqlNullString(orgReq.PhoneNumber),
					Address:      wrUtil.NewSqlNullString(orgReq.Address),
					Description:  wrUtil.NewSqlNullString(orgReq.Description),
				},
			},
		},
	}

	logger.Debugf("OrgCredential %v, Type: %T", orgInfo, orgInfo)

	ctx := c.Request().Context()

	// organizationの作成トランザクション
	if err := oh.tm.DoInTransaction(c, ctx, func(tx *gorm.DB) error {

		// organizationの作成
		orgID, wrErr := oh.osr.CreateOrg(tx, c, &orgInfo.AuthDogrunmg.Dogrunmg.Organization)

		if wrErr != nil {
			return wrErr
		}

		// Organizationが作成された後、そのIDをDogrun MGに設定
		orgInfo.AuthDogrunmg.Dogrunmg.OrganizationID = orgID

		// dogrunmgの作成
		dmID, wrErr := oh.dmsr.CreateDogrunmg(tx, c, &orgInfo.AuthDogrunmg.Dogrunmg)

		if wrErr != nil {
			return wrErr
		}

		// Dogrunmgが作成された後、そのIDをauthDogrunmgに設定
		orgInfo.AuthDogrunmg.DogrunmgID = dmID

		// AuthDogrunmgの作成
		admID, wrErr := oh.asr.CreateAuthDogrunmg(tx, c, &orgInfo.AuthDogrunmg)

		if wrErr != nil {
			return wrErr
		}

		// AuthDogrunmgが作成された後、そのIDをdogrunmgCredentialに設定
		orgInfo.AuthDogrunmgID = admID

		// DogrunmgのCredentialsの作成
		if wrErr := oh.asr.CreateDogrunmgCredential(tx, c, &orgInfo); wrErr != nil {
			return wrErr
		}

		// 正常に完了
		return nil

	}); err != nil {
		logger.Error("Transaction failed:", err)
		return authDTO.IssuedJwT{}, err
	}

	// 作成したdogrunmgの情報をdto詰め替え
	dogrunmgrDetail := authDTO.JwtInfoDTO{
		AuthUserInfoDTO: authDTO.AuthUserInfoDTO{
			UserID: orgInfo.AuthDogrunmg.DogrunmgID.Int64,
			RoleID: core.DOGRUNMG_ADMIN_ROLE,
		},
		JwtID: orgInfo.AuthDogrunmg.JwtID.String,
	}

	logger.Infof("dogrunmgDetail: %v", dogrunmgrDetail)

	// 署名済みのjwt token取得
	token, refreshToken, wrErr := authHandler.GetSignedJwt(c, dogrunmgrDetail)

	if wrErr != nil {
		return authDTO.IssuedJwT{}, wrErr
	}

	return authDTO.IssuedJwT{AccessToken: token, RefreshToken: refreshToken}, nil
}
