package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/auth/core"
	"github.com/wanrun-develop/wanrun/internal/wrcontext"
	"github.com/wanrun-develop/wanrun/pkg/errors"
)

// 全ロール
var ALL = []int{
	core.SYSTEM,
	core.DOGOWNER_ROLE,
	core.DOGRUNMG_ADMIN_ROLE,
	core.DOGRUNMG_ROLE,
	core.GENERAL,
}

// システムロールのみ (ミドルウェアでシステムユーザーは全て許可済み)
var SYSTEM = []int{}

// ドッグラン参照
var DOGRUN_REFER = []int{
	core.DOGOWNER_ROLE,
	core.GENERAL,
	core.DOGRUNMG_ADMIN_ROLE,
	core.DOGRUNMG_ROLE,
}

// ドッグラン検索
var DOGRUN_SEARCH = []int{
	core.DOGOWNER_ROLE,
	core.GENERAL,
}

// 犬管理
var DOG_MANAGE = []int{
	core.DOGOWNER_ROLE,
}

// ドッグラン管理
var DOGRUN_MANAGE = []int{
	core.DOGRUNMG_ADMIN_ROLE,
	core.DOGRUNMG_ROLE,
}

// ドッグラン特権管理
var DOGRUN_SUPER_MANAGE = []int{
	core.DOGRUNMG_ADMIN_ROLE,
}

// RoleAuthorization: ロール認可
// トークン認証後、コンテキストのclaim情報からRoleを取得し、認可を検証
//
// args:
//   - echo.Context:	コンテキスト
//   - []int:	認可対象のロール
//
// return:
//   - echo.MiddlewareFunc:	ミドルウェア
func RoleAuthorization(allowedRoles []int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userRole, err := wrcontext.GetLoginUserRole(c) // Contextからユーザーのロールを取得
			if err != nil {
				err = errors.NewWRError(err, "ユーザーのロール認可で失敗しました。", errors.NewAuthServerErrorEType())
				return err
			}

			//システムユーザーはチェック対象外
			for _, systemRole := range SYSTEM {
				if userRole == systemRole {
					err := next(c)
					return err
				}
			}

			//引数の認可対象であるかチェック
			for _, allowedRole := range allowedRoles {
				if userRole == allowedRole {
					err := next(c) // 許可されたロールの場合、次へ進む
					return err
				}
			}

			return errors.NewWRError(nil, "あなたのユーザーではご利用できない機能です。", errors.NewAuthClientErrorEType())
		}
	}
}
