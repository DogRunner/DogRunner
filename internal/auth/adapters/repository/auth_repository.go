package repository

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/auth/core/dto"
	model "github.com/wanrun-develop/wanrun/internal/models"
	wrErrors "github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	"gorm.io/gorm"
)

type IAuthRepository interface {
	CreateDogOwner(c echo.Context, doc *model.DogOwnerCredential) (*model.DogOwnerCredential, error)
	GetDogOwnerByCredentials(c echo.Context, adoReq dto.AuthDogOwnerReq) ([]model.DogOwnerCredential, error)
	GetAuthDogOwnerByID(c echo.Context, dogownerID int64) (model.AuthDogOwner, error)
	// CreateOAuthDogOwner(c echo.Context, dogOwnerCredential *model.DogOwnerCredential) (*model.DogOwnerCredential, error)
	UpdateDogownerJwtID(c echo.Context, doID int64, ji string, rji string) error
	GetJwtID(c echo.Context, userID int64, modelType any, result any, columnName string) (string, error)
	GetDogownerJwtID(c echo.Context, dogownerID int64) (string, error)
	GetDogrunmgJwtID(c echo.Context, dogownerID int64) (string, error)
	DeleteDogownerJwtID(c echo.Context, doID int64) error
	CheckDuplicate(c echo.Context, field string, value sql.NullString) error
	CountOrgEmail(c echo.Context, email string) (int64, error)
	GetDogrunmgByCredentials(c echo.Context, email string) ([]model.DogrunmgCredential, error)
	UpdateDogrunmgJwtID(c echo.Context, dmID int64, ji string) error
	DeleteDogrunmgJwtID(c echo.Context, dmID int64) error
}

type authRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) IAuthRepository {
	return &authRepository{db}
}

// CreateDogOwner: DogOwnerの作成
//
// args:
//   - echo.Context: c Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - *model.DogOwnerCredential: doc ドッグオーナーのクレデンシャル
//
// return:
//   - *model.DogOwnerCredential: ドッグオーナーのクレデンシャル
//   - error: error情報
func (ar *authRepository) CreateDogOwner(c echo.Context, doc *model.DogOwnerCredential) (*model.DogOwnerCredential, error) {
	logger := log.GetLogger(c).Sugar()

	// Emailの重複チェック
	if wrErr := ar.CheckDuplicate(c, model.EmailField, doc.Email); wrErr != nil {
		return nil, wrErr
	}

	// PhoneNumberの重複チェック
	if wrErr := ar.CheckDuplicate(c, model.PhoneNumberField, doc.PhoneNumber); wrErr != nil {
		return nil, wrErr
	}

	// トランザクションの開始
	err := ar.db.Transaction(func(tx *gorm.DB) error {
		// dog_ownersテーブルにレコード作成
		if err := tx.Create(&doc.AuthDogOwner.DogOwner).Error; err != nil {
			logger.Error("Failed to DogOwner: ", err)
			return err
		}

		// DogOwnerが作成された後、そのIDをauthDogOwnerに設定
		doc.AuthDogOwner.DogOwnerID = doc.AuthDogOwner.DogOwner.DogOwnerID

		// auth_dog_ownersテーブルにレコード作成
		if err := tx.Create(&doc.AuthDogOwner).Error; err != nil {
			logger.Error("Failed to AuthDogOwner: ", err)
			return err
		}
		// AuthDogOwnerが作成された後、そのIDをdogOwnerCredentialに設定
		doc.AuthDogOwnerID = doc.AuthDogOwner.AuthDogOwnerID

		// dog_owner_credentialsテーブルにレコード作成
		if err := tx.Create(&doc).Error; err != nil {
			logger.Error("Failed to DogOwnerCredential: ", err)
			return err
		}
		return nil
	})

	if err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBへの登録が失敗しました。",
			wrErrors.NewDogOwnerServerErrorEType())

		logger.Errorf("Transaction failed error: %v", wrErr)

		return nil, wrErr
	}

	logger.Infof("Created DogOwner Detail: %v", doc.AuthDogOwner.DogOwner)
	logger.Infof("Created AuthDogOwner Detail: %v", doc.AuthDogOwner)
	logger.Infof("Created DogOwnerCredential Detail: %v", doc)

	return doc, nil
}

/*
OAuthユーザーの作成
*/
// func (ar *authRepository) CreateOAuthDogOwner(c echo.Context, doc *model.DogOwnerCredential) (*model.DogOwnerCredential, error) {
// 	logger := log.GetLogger(c).Sugar()

// 	// Emailの確認
// 	if wrErr := ar.checkDuplicate(c, model.PhoneNumberField, doc); wrErr != nil {
// 		return nil, wrErr
// 	}

// 	// PhoneNumberの確認

// 	// トランザクションの開始
// 	err := ar.db.Transaction(func(tx *gorm.DB) error {
// 		// dog_ownersテーブルにレコード作成
// 		if err := tx.Create(&doc.AuthDogOwner.DogOwner).Error; err != nil {
// 			logger.Error("Failed to DogOwner: ", err)
// 			return err
// 		}

// 		// DogOwnerが作成された後、そのIDをauthDogOwnerに設定
// 		doc.AuthDogOwner.DogOwnerID = doc.AuthDogOwner.DogOwner.DogOwnerID

// 		// auth_dog_ownersテーブルにレコード作成
// 		if err := tx.Create(&doc.AuthDogOwner).Error; err != nil {
// 			logger.Error("Failed to AuthDogOwner: ", err)
// 			return err
// 		}

// 		// AuthDogOwnerが作成された後、そのIDをdogOwnerCredentialに設定
// doc.AuthDogOwnerID = doc.AuthDogOwner.AuthDogOwnerID
// 		// dog_owner_credentialsテーブルにレコード作成
// 		if err := tx.Create(&doc).Error; err != nil {
// 			logger.Error("Failed to DogOwnerCredential: ", err)
// 			return err
// 		}
// 		return nil
// 	})

// 	if err != nil {
// 		wrErr := wrErrors.NewWRError(
// 			err,
// 			"transaction failed",
// 			wrErrors.NewDogOwnerClientErrorEType())

// 		logger.Errorf("Transaction failed error: %v", wrErr)

// 		return nil, wrErr
// 	}

// 	logger.Infof("Created DogOwner Detail: %v", doc.AuthDogOwner.DogOwner)
// 	logger.Infof("Created AuthDogOwner Detail: %v", doc.AuthDogOwner)
// 	logger.Infof("Created DogOwnerCredential Detail: %v", doc)

// 	// レスポンス用にDogOwnerのクレデンシャル取得
// 	var result model.DogOwnerCredential
// 	err = ar.db.Preload("AuthDogOwner").Preload("AuthDogOwner.DogOwner").First(&result, doc.CredentialID).Error

// 	if err != nil {
// 		wrErr := wrErrors.NewWRError(
// 			err,
// 			"failed to fetch created record",
// 			wrErrors.NewDogOwnerServerErrorEType())

// 		logger.Errorf("Failed to fetch created record: %v", wrErr)

// 		return nil, wrErr
// 	}

// 	logger.Infof("Created DogOwnerCredential Detail: %v", result)

// 	return &result, nil
// }

// GetDogOwnerByCredentials: ドッグオーナーのクレデンシャル取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - dto.AuthDogOwnerReq: authDogOwnerのリクエスト情報
//
// return:
//   - *model.DogOwnerCredential: ドッグオーナーのクレデンシャル
//   - error: error情報
func (ar *authRepository) GetDogOwnerByCredentials(c echo.Context, adoReq dto.AuthDogOwnerReq) ([]model.DogOwnerCredential, error) {
	logger := log.GetLogger(c).Sugar()

	var results []model.DogOwnerCredential

	// EmailまたはPhoneNumberとgrantTypeがPASSWORDに基づくレコードを検索
	if err := ar.db.Model(&model.DogOwnerCredential{}).
		Preload("AuthDogOwner").
		Preload("AuthDogOwner.DogOwner").
		Where("(email = ? OR phone_number = ?) AND grant_type = ?", adoReq.Email, adoReq.PhoneNumber, model.PASSWORD_GRANT_TYPE).
		Find(&results).
		Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("DB search failure: %v", wrErr)

		return []model.DogOwnerCredential{}, wrErr
	}

	logger.Debugf("Query Results: %v", results)

	return results, nil
}

// GetAuthDogOwnerByID: ドッグオーナーのクレデンシャル取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: authDogOwnerのリクエスト情報
//
// return:
//   - *model.DogOwnerCredential: ドッグオーナーのクレデンシャル
//   - error: error情報
func (ar *authRepository) GetAuthDogOwnerByID(c echo.Context, dogOwnerID int64) (model.AuthDogOwner, error) {
	logger := log.GetLogger(c).Sugar()

	var result model.AuthDogOwner

	if err := ar.db.Model(&model.AuthDogOwner{}).
		Where("dog_owner_id = ?", dogOwnerID).
		First(&result).Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("DB search failure: %v", wrErr)

		return result, wrErr
	}
	logger.Debugf("Query Results: %v", result)

	return result, nil
}

// UpdateDogownerJwtID: 対象のdogownerのjwt_idの更新
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: dogownerのPK
//   - string: 更新用のjwt_id
//
// return:
//   - error: error情報
func (ar *authRepository) UpdateDogownerJwtID(
	c echo.Context,
	doID int64,
	ji string,
	rji string,
) error {
	logger := log.GetLogger(c).Sugar()

	// 対象のdogownerのjwt_idの更新
	err := ar.db.Model(&model.AuthDogOwner{}).
		Where("dog_owner_id= ?", doID).
		Update("jwt_id", ji).Update("refresh_jwt_id", rji).Error

	if err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBへの更新が失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Failed to update JWT ID: %v", wrErr)

		return wrErr
	}

	return nil
}

// DeleteDogownerJwtID: 対象のdogownerのjwt_id,refresh_jwt_idの削除
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - dto.DogownerDTO: dogownerの情報
//
// return:
//   - error: error情報
func (ar *authRepository) DeleteDogownerJwtID(c echo.Context, doID int64) error {
	logger := log.GetLogger(c).Sugar()

	// 対象のdogOwnerのjwt_idの更新
	if err := ar.db.Model(&model.AuthDogOwner{}).
		Where("dog_owner_id= ?", doID).
		Update("jwt_id", nil).Update("refresh_jwt_id", nil).Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBへの同期が失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)

		logger.Errorf("Failed to delete dogowner JWT ID: %v", wrErr)

		return wrErr
	}

	return nil
}

// DeleteDogrunmgJwtID: 対象のdogrunmgのjwt_idの削除
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: dogrunmgのID
//
// return:
//   - error: error情報
func (ar *authRepository) DeleteDogrunmgJwtID(c echo.Context, dmID int64) error {
	logger := log.GetLogger(c).Sugar()

	// 対象のdogrunmgのjwt_idの更新
	if err := ar.db.Model(&model.AuthDogrunmg{}).
		Where("dogrun_manager_id= ?", dmID).
		Update("jwt_id", nil).Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBへの同期が失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)

		logger.Errorf("Failed to delete dogrunmg JWT ID: %v", wrErr)

		return wrErr
	}

	return nil
}

// GetJwtID: dogrunmgとdogonwerのjwtIDの取得(共通処理)
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: 取得したいdogrunmgIDかdogownerID
//   - any: modelType クエリ対象の構造体
//   - any: result 検索結果の格納する構造体
//   - string: 検索カラム名(dogrunmgIDかdogownerID)
//
// return:
//   - string: 対象のjwt_id
//   - error: error情報
func (ar *authRepository) GetJwtID(
	c echo.Context,
	userID int64,
	modelType any,
	result any,
	columnName string,
) (string, error) {
	logger := log.GetLogger(c).Sugar()

	// バリデーション関数
	validateModel := func(value any, purpose string) error {
		switch value.(type) {
		// Authのdogrunmgかdogownerの型チェック
		case *model.AuthDogOwner, *model.AuthDogrunmg:
			// バリデーションOK
		default:
			logger.Errorf("Invalid %s model type: %T", purpose, value)

			return wrErrors.NewWRError(
				nil,
				fmt.Sprintf("%sが無効な構造体の型です。", purpose),
				wrErrors.NewUnexpectedErrorEType(),
			)
		}
		return nil
	}

	// modelTypeのバリデーション
	if err := validateModel(modelType, "クエリ対象"); err != nil {
		return "", err
	}

	// resultのバリデーション
	if err := validateModel(result, "結果格納先"); err != nil {
		return "", err
	}

	// 対象のjwt_id取得
	err := ar.db.Model(modelType).
		Where(columnName+" = ?", userID).
		First(result).
		Error

	if err != nil {
		// jwt_idが見つからない場合
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Errorf("Not found jwt id error for %s: %v", columnName, err)
			return "", wrErrors.NewWRError(
				err,
				"認証情報がありません",
				wrErrors.NewAuthClientErrorEType(),
			)
		}

		logger.Errorf("Failed to get JWT ID for %s: %v", columnName, err)

		// その他DB関連のエラー処理
		return "", wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)
	}
	logger.Debugf("Query Result: %v", result)

	// JWT ID取得
	switch v := result.(type) {
	case *model.AuthDogOwner:
		return v.JwtID.String, nil
	case *model.AuthDogrunmg:
		return v.JwtID.String, nil
	default:
		logger.Errorf("Unexpected model type after query: %T", result)
		return "", wrErrors.NewWRError(
			nil,
			"予期しないモデルタイプです。",
			wrErrors.NewUnexpectedErrorEType(),
		)
	}
}

// GetDogownerJwtID: dogonwerのjwtIDの取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: 取得したいdogownerID
//
// return:
//   - string: 対象のjwt_id
//   - error: error情報
func (ar *authRepository) GetDogownerJwtID(c echo.Context, dogownerID int64) (string, error) {
	logger := log.GetLogger(c).Sugar()

	var result model.AuthDogOwner

	// 対象のdogOwnerのjwt_idの取得
	err := ar.db.Model(&model.AuthDogOwner{}).
		Where("dog_owner_id= ?", dogownerID).
		First(&result).
		Error

	if err != nil {
		// 空だった時
		if errors.Is(err, gorm.ErrRecordNotFound) {
			wrErr := wrErrors.NewWRError(
				err,
				"認証情報がありません",
				wrErrors.NewAuthClientErrorEType())

			logger.Errorf("Not found jwt id error: %v", wrErr)

			return "", wrErr
		}

		// その他のエラー処理
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Failed to get JWT ID: %v", wrErr)

		return "", wrErr
	}

	logger.Debugf("Query Result: %v", result)

	return result.JwtID.String, nil

}

// GetDogrunmgJwtID: dogrunmgのjwtIDの取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: 取得したいdogrunmgID
//
// return:
//   - string: 対象のjwt_id
//   - error: error情報
func (ar *authRepository) GetDogrunmgJwtID(c echo.Context, dogrunmgID int64) (string, error) {
	logger := log.GetLogger(c).Sugar()

	var result model.AuthDogrunmg

	// 対象のdogrunmgのjwt_idの取得
	err := ar.db.Model(&model.AuthDogrunmg{}).
		Where("dogrun_manager_id= ?", dogrunmgID).
		First(&result).
		Error

	if err != nil {
		// 空だった時
		if errors.Is(err, gorm.ErrRecordNotFound) {
			wrErr := wrErrors.NewWRError(
				err,
				"認証情報がありません",
				wrErrors.NewAuthClientErrorEType())

			logger.Errorf("Not found jwt id error: %v", wrErr)

			return "", wrErr
		}

		// その他のエラー処理
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Failed to get JWT ID: %v", wrErr)

		return "", wrErr
	}

	logger.Debugf("Query Result: %v", result)

	return result.JwtID.String, nil

}

// CheckDuplicate:  Password認証のバリデーション
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - string: 対象のdbのフィールド名
//   - sql.NullString: 対象のgrant_typeの値
//
// return:
//   - error: error情報
func (ar *authRepository) CheckDuplicate(c echo.Context, field string, value sql.NullString) error {
	logger := log.GetLogger(c).Sugar()

	// 重複のvalidate
	var existingCount int64

	// grant_typeがPASSWORDで重複していないかの確認
	if err := ar.db.Model(&model.DogOwnerCredential{}).
		Where(field+" = ? AND grant_type = ?", value, model.PASSWORD_GRANT_TYPE).
		Count(&existingCount).
		Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)

		logger.Errorf("Failed to check existing value error: %v", wrErr)

		return wrErr
	}

	if existingCount > 0 {
		wrErr := wrErrors.NewWRError(
			nil,
			fmt.Sprintf("%sの%sが既に登録されています。", field, value.String),
			wrErrors.NewDogOwnerClientErrorEType(),
		)

		logger.Errorf("%s already exists error: %v", field, wrErr)

		return wrErr
	}
	return nil
}

// CountOrgEmail:  OrgのEmail数の取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - string: 対象のEmail
//
// return:
//   - int64: OrgのEmailの数
//   - error: error情報
func (ar *authRepository) CountOrgEmail(c echo.Context, email string) (int64, error) {
	logger := log.GetLogger(c).Sugar()

	// email数の取得数
	var existingCount int64

	// Emailの数の取得
	if err := ar.db.Model(&model.DogrunmgCredential{}).
		Where("email"+" = ?", email).
		Count(&existingCount).
		Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)

		logger.Errorf("Failed to check existing value error: %v", wrErr)

		return 0, wrErr
	}

	return existingCount, nil
}

// GetDogrunmgByCredentials: Emailを元にdogrunmgのクレデンシャル取得
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - string: authDogrunmgのemail
//
// return:
//   - []model.DogrunmgCredential: 取得したdogrunmgの情報
//   - error: error情報
func (ar *authRepository) GetDogrunmgByCredentials(c echo.Context, email string) ([]model.DogrunmgCredential, error) {
	logger := log.GetLogger(c).Sugar()

	var results []model.DogrunmgCredential
	// Emailに基づくレコードを検索
	if err := ar.db.Model(&model.DogrunmgCredential{}).
		Preload("AuthDogrunmg").          // AuthDogrunmgをロード
		Preload("AuthDogrunmg.Dogrunmg"). // AuthDogrunmgに紐づくDogrunmgをロード
		Where("email = ?", email).
		Find(&results).Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBからのデータ取得に失敗しました。",
			wrErrors.NewAuthServerErrorEType(),
		)

		logger.Errorf("DB search failure: %v", wrErr)

		return nil, wrErr
	}

	logger.Debugf("Query Result: %v", results)

	return results, nil
}

// UpdateDogrunmgJwtID: 対象のdogrunmgのjwt_idの更新
//
// args:
//   - echo.Context: Echoのコンテキスト。リクエストやレスポンスにアクセスするために使用
//   - int64: dogrunmgのPK
//   - string: 更新用のjwt_id
//
// return:
//   - error: error情報
func (ar *authRepository) UpdateDogrunmgJwtID(
	c echo.Context,
	dmID int64,
	ji string,
) error {
	logger := log.GetLogger(c).Sugar()

	// 対象のdogrunmgのjwt_idの更新
	if err := ar.db.Model(&model.AuthDogrunmg{}).
		Where("dogrun_manager_id= ?", dmID).
		Update("jwt_id", ji).Error; err != nil {
		wrErr := wrErrors.NewWRError(
			err,
			"DBへの更新が失敗しました。",
			wrErrors.NewAuthServerErrorEType())

		logger.Errorf("Failed to update JWT ID: %v", wrErr)

		return wrErr
	}

	return nil
}
