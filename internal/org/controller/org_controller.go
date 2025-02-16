package controller

import (
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/org/core/dto"
	orgHandler "github.com/wanrun-develop/wanrun/internal/org/core/handler"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
)

type IOrgController interface {
	OrgSignUp(c echo.Context) error
}

type orgController struct {
	oh orgHandler.IOrgHandler
}

func NewOrgController(
	oh orgHandler.IOrgHandler,
) IOrgController {
	return &orgController{
		oh: oh,
	}
}

func (o *orgController) OrgSignUp(c echo.Context) error {
	logger := log.GetLogger(c).Sugar()

	orgReq := dto.OrgReq{}

	if err := c.Bind(&orgReq); err != nil {
		wrErr := errors.NewWRError(
			err,
			"入力項目に不正があります。",
			errors.NewOrgClientErrorEType(),
		)
		logger.Error(wrErr)
		return wrErr
	}

	// バリデータのインスタンス作成
	validate := validator.New()

	//リクエストボディのバリデーション
	if err := validate.Struct(&orgReq); err != nil {
		err = errors.NewWRError(
			err,
			"必須の項目に不正があります。",
			errors.NewOrgClientErrorEType(),
		)
		logger.Error(err)
		return err
	}

	// organizationのSignUp
	token, wrErr := o.oh.OrgSignUp(c, orgReq)

	if wrErr != nil {
		return wrErr
	}

	return c.JSON(http.StatusCreated, token)
}
