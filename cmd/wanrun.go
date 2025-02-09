package wanruncmd

import (
	"context"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/wanrun-develop/wanrun/configs"
	"github.com/wanrun-develop/wanrun/internal"

	//auth
	authRepository "github.com/wanrun-develop/wanrun/internal/auth/adapters/repository"
	authController "github.com/wanrun-develop/wanrun/internal/auth/controller"
	authFacade "github.com/wanrun-develop/wanrun/internal/auth/core/facade"
	authHandler "github.com/wanrun-develop/wanrun/internal/auth/core/handler"
	authMW "github.com/wanrun-develop/wanrun/internal/auth/middleware"

	//cms
	cmsAWS "github.com/wanrun-develop/wanrun/internal/cms/adapters/aws"
	cmsRepository "github.com/wanrun-develop/wanrun/internal/cms/adapters/repository"
	cmsController "github.com/wanrun-develop/wanrun/internal/cms/controller"
	cmsHandler "github.com/wanrun-develop/wanrun/internal/cms/core/handler"

	//dog
	dogRepository "github.com/wanrun-develop/wanrun/internal/dog/adapters/repository"
	dogController "github.com/wanrun-develop/wanrun/internal/dog/controller"
	dogHandler "github.com/wanrun-develop/wanrun/internal/dog/core/handler"
	dogF "github.com/wanrun-develop/wanrun/internal/dog/facade"

	//dogowner
	dogOwnerRepository "github.com/wanrun-develop/wanrun/internal/dogowner/adapters/repository"
	dogOwnerController "github.com/wanrun-develop/wanrun/internal/dogowner/controller"
	dogOwnerHandler "github.com/wanrun-develop/wanrun/internal/dogowner/core/handler"

	//dogrun
	"github.com/wanrun-develop/wanrun/internal/dogrun/adapters/googleplace"
	dogrunR "github.com/wanrun-develop/wanrun/internal/dogrun/adapters/repository"
	dogrunC "github.com/wanrun-develop/wanrun/internal/dogrun/controller"
	dogrunH "github.com/wanrun-develop/wanrun/internal/dogrun/core/handler"
	dogrunF "github.com/wanrun-develop/wanrun/internal/dogrun/facade"

	//dogrunmg
	dogrunmgRepository "github.com/wanrun-develop/wanrun/internal/dogrunmg/adapters/repository"

	//org
	orgRepository "github.com/wanrun-develop/wanrun/internal/org/adapters/repository"
	orgController "github.com/wanrun-develop/wanrun/internal/org/controller"
	orgHandler "github.com/wanrun-develop/wanrun/internal/org/core/handler"

	//interaction
	interactionR "github.com/wanrun-develop/wanrun/internal/interaction/adapters/repository"
	interactionC "github.com/wanrun-develop/wanrun/internal/interaction/controller"
	interactionH "github.com/wanrun-develop/wanrun/internal/interaction/core/handler"
	interactionFacade "github.com/wanrun-develop/wanrun/internal/interaction/facade"

	//other
	"github.com/wanrun-develop/wanrun/internal/db"
	"github.com/wanrun-develop/wanrun/internal/transaction"

	"github.com/wanrun-develop/wanrun/pkg/errors"
	logger "github.com/wanrun-develop/wanrun/pkg/log"
	"gorm.io/gorm"
)

func init() {

}

func Main() {
	dbConn, err := db.NewDB()
	if err != nil {
		log.Fatalln(err)
	}

	defer db.CloseDB(dbConn)

	e := echo.New()

	// グローバルロガーの初期化
	zap := logger.NewWanRunLogger()
	logger.SetLogger(zap) // グローバルロガーを設定
	// アプリケーション終了時にロガーを同期
	defer zap.Sync()

	// CORSの設定
	e.Use(middleware.CORS())

	// ミドルウェアを登録
	e.Use(middleware.RequestID())
	e.HTTPErrorHandler = errors.HttpErrorHandler
	e.Use(logger.RequestLoggerMiddleware(zap))

	// JWTミドルウェアの設定
	authMiddleware := newAuthMiddleware(dbConn)
	e.Use(authMiddleware.NewJwtValidationMiddleware())

	// Router設定
	newRouter(e, dbConn)
	e.GET("/test", internal.Test, authMW.RoleAuthorization(authMW.ALL))

	// 最大リクエストボディサイズの指定
	e.Use(middleware.BodyLimit("10M")) // 最大10MB

	e.Logger.Fatal(e.Start(":8080"))
}

func newRouter(e *echo.Echo, dbConn *gorm.DB) {
	// dog関連
	dogController := newDog(dbConn)
	dog := e.Group("dog")
	dog.GET("/all", dogController.GetAllDogs, authMW.RoleAuthorization(authMW.SYSTEM))
	dog.GET("/detail/:dogID", dogController.GetDogByID, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	dog.GET("/owned/:dogOwnerId", dogController.GetDogByDogOwnerID, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	dog.GET("/mst/dogType", dogController.GetDogTypeMst, authMW.RoleAuthorization(authMW.ALL))
	dog.POST("", dogController.CreateDog, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	dog.PUT("", dogController.UpdateDog, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	dog.DELETE("", dogController.DeleteDog, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	// dog.PUT("/:dogID", dogController.UpdateDog)

	// dogrun関連
	dogrunController := newDogrun(dbConn)
	dogrun := e.Group("dogrun")
	dogrun.GET("/detail/:placeId", dogrunController.GetDogrunDetail, authMW.RoleAuthorization(authMW.DOGRUN_REFER))
	dogrun.GET("/:id", dogrunController.GetDogrun, authMW.RoleAuthorization(authMW.DOGRUN_REFER))
	dogrun.GET("/photo/src", dogrunController.GetDogrunPhoto, authMW.RoleAuthorization(authMW.DOGRUN_REFER))
	dogrun.GET("/mst/tag", dogrunController.GetDogrunTagMst, authMW.RoleAuthorization(authMW.ALL))
	dogrun.POST("/search", dogrunController.SearchAroundDogruns, authMW.RoleAuthorization(authMW.DOGRUN_SEARCH))

	// dogOwner関連
	dogOwnerController := newDogOwner(dbConn)
	dogOwner := e.Group("dogowner")
	dogOwner.POST("/signUp", dogOwnerController.DogOwnerSignUp)

	// auth関連
	authController := newAuth(dbConn)
	auth := e.Group("auth")
	// dogowner
	auth.POST("/dogowner/token", authController.LogInDogowner)
	auth.POST("/dogowner/revoke", authController.RevokeDogowner, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	// auth.GET("/google/oauth", authController.GoogleOAuth)
	// dogrunmg
	auth.POST("/dogrunmg/token", authController.LogInDogrunmg)
	auth.POST("/dogrunmg/revoke", authController.RevokeDogrunmg, authMW.RoleAuthorization(authMW.DOGRUN_MANAGE))
	//general
	auth.GET("/general/token", authController.IssueGeneralUserToke)

	//interaction関連
	interactionController := newInteraction(dbConn)
	bookmark := e.Group("bookmark")
	bookmark.POST("/dogrun", interactionController.AddBookmark, authMW.RoleAuthorization(authMW.DOGRUN_SEARCH))
	bookmark.DELETE("/dogrun", interactionController.DeleteBookmarks, authMW.RoleAuthorization(authMW.DOGRUN_SEARCH))

	access := e.Group("access")
	access.GET("/today/checkins", interactionController.GetTodayCheckins, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	access.POST("/checkin", interactionController.CheckinDogrun, authMW.RoleAuthorization(authMW.DOG_MANAGE))
	access.DELETE("/checkout", interactionController.CheckoutDogrun, authMW.RoleAuthorization(authMW.DOG_MANAGE))

	// cms関連
	cmsController := newCms(dbConn)
	cms := e.Group("cms")
	cms.POST("/upload/file", cmsController.UploadFile, authMW.RoleAuthorization(authMW.ALL))
	cms.DELETE("", cmsController.DeleteFile, authMW.RoleAuthorization(authMW.ALL))

	// ヘルスチェック
	e.GET("/health", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	// org関連
	orgController := newOrg(dbConn)
	org := e.Group("org")
	org.POST("/contract", orgController.OrgSignUp)
}

// dogの初期化
func newDog(dbConn *gorm.DB) dogController.IDogController {
	dogRepository := dogRepository.NewDogRepository(dbConn)
	dogOwnerRepository := dogOwnerRepository.NewDogRepository(dbConn)
	dogHandler := dogHandler.NewDogHandler(dogRepository, dogOwnerRepository)
	dogController := dogController.NewDogController(dogHandler)
	return dogController
}

func newDogrun(dbConn *gorm.DB) dogrunC.IDogrunController {
	//facadeの準備
	interactionRepository := interactionR.NewBookmarkRepository(dbConn)
	dogrunFacade := interactionFacade.NewBookmarkFacade(interactionRepository)

	dogrunRest := googleplace.NewRest()
	dogrunRepository := dogrunR.NewDogrunRepository(dbConn)
	dogrunHandler := dogrunH.NewDogrunHandler(dogrunRest, dogrunRepository, dogrunFacade)
	return dogrunC.NewDogrunController(dogrunHandler)
}

func newAuth(dbConn *gorm.DB) authController.IAuthController {
	authRepository := authRepository.NewAuthRepository(dbConn)
	// googleOAuth := google.NewOAuthGoogle()
	// authHandler := authHandler.NewAuthHandler(authRepository, googleOAuth)
	authHandler := authHandler.NewAuthHandler(authRepository)
	authController := authController.NewAuthController(authHandler)
	return authController
}

func newAuthMiddleware(dbConn *gorm.DB) authMW.IAuthJwt {
	authRepository := authRepository.NewAuthRepository(dbConn)
	return authMW.NewAuthJwt(authRepository)
}

func newInteraction(dbConn *gorm.DB) interactionC.IInteractionController {
	//dogrun facadeの準備
	dogrunRepository := dogrunR.NewDogrunRepository(dbConn)
	dogrunFacade := dogrunF.NewDogrunFacade(dogrunRepository)
	//dog facadeの準備
	dogRepository := dogRepository.NewDogRepository(dbConn)
	dogFacade := dogF.NewDogFacade(dogRepository)

	//bookmark
	bookmarkRepository := interactionR.NewBookmarkRepository(dbConn)
	bookmarkHandler := interactionH.NewBookmarkHandler(bookmarkRepository, dogrunFacade)
	//checkinout
	checkInOutRepository := interactionR.NewCheckInOutRepository(dbConn)
	checkInOutHandler := interactionH.NewCheckInOutHandler(checkInOutRepository, dogrunFacade, dogFacade)

	return interactionC.NewInteractionController(bookmarkHandler, checkInOutHandler)
}

// dogOwnerの初期化
func newDogOwner(dbConn *gorm.DB) dogOwnerController.IDogOwnerController {
	// repository層
	dor := dogOwnerRepository.NewDogRepository(dbConn)
	ar := authRepository.NewAuthRepository(dbConn)

	// transaction層
	transactionManager := transaction.NewTransactionManager(dbConn)

	// scopeRepository層
	dosr := dogOwnerRepository.NewDogOwnerScopeRepository()
	asr := authRepository.NewAuthScopeRepository()

	// handler層
	authHandler := authHandler.NewAuthHandler(ar)
	dogOwnerHandler := dogOwnerHandler.NewDogOwnerHandler(
		dosr,
		transactionManager,
		asr,
		dor,
		ar,
	)

	// controller層
	return dogOwnerController.NewDogOwnerController(dogOwnerHandler, authHandler)
}

func newCms(dbConn *gorm.DB) cmsController.ICmsController {
	cmsRepository := cmsRepository.NewCmsRepository(dbConn)
	// aws設定
	sdkCfg, err := loadAWSConfig()

	if err != nil {
		log.Fatalf("AWSのクレデンシャル取得に失敗: %v", err)
	}
	cmsAWS := cmsAWS.NewS3Provider(sdkCfg)
	cmsHandler := cmsHandler.NewCmsHandler(cmsAWS, cmsRepository)
	cmsController := cmsController.NewCmsController(cmsHandler)
	return cmsController
}

func loadAWSConfig() (aws.Config, error) {
	// local
	if configs.FetchConfigStr("ENV") == "local" {
		return config.LoadDefaultConfig(context.Background(),
			config.WithRegion(cmsAWS.DEFAULT_REGION),
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					configs.FetchConfigStr("aws.access.key"),
					configs.FetchConfigStr("aws.secret.access.key"),
					"",
				),
			),
		)
	}

	// クラウド
	return config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cmsAWS.DEFAULT_REGION),
	)
}

func newOrg(dbConn *gorm.DB) orgController.IOrgController {
	// repository層
	// orgRepository := orgRepository.NewOrgRepository(dbConn)
	ar := authRepository.NewAuthRepository(dbConn)

	// scopeRepository層
	orgScopeRepository := orgRepository.NewOrgScopeRepository()
	dogrunmgScopeRepository := dogrunmgRepository.NewDogrunmgScopeRepository()
	authScopeRepository := authRepository.NewAuthScopeRepository()

	// transaction層
	transactionManager := transaction.NewTransactionManager(dbConn)

	// facade層
	authFacade := authFacade.NewAuthFacade(ar)

	// handler層
	orgHandler := orgHandler.NewOrgHandler(
		orgScopeRepository,
		transactionManager,
		dogrunmgScopeRepository,
		authScopeRepository,
		authFacade,
	)

	// controller層
	return orgController.NewOrgController(orgHandler)
}
