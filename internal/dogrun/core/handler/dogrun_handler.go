package handler

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/wanrun-develop/wanrun/internal/dogrun/adapters/googleplace"
	"github.com/wanrun-develop/wanrun/internal/dogrun/adapters/repository"
	"github.com/wanrun-develop/wanrun/internal/dogrun/core/dto"
	"github.com/wanrun-develop/wanrun/internal/interaction/facade"
	model "github.com/wanrun-develop/wanrun/internal/models"
	"github.com/wanrun-develop/wanrun/pkg/errors"
	"github.com/wanrun-develop/wanrun/pkg/log"
	"github.com/wanrun-develop/wanrun/pkg/util"
)

const (
	SEARCH_TEXT_MAX_REQUEST_TIMES = 3 //searchTextの最大リクエスト数。pageSizeを20に指定すると、20*3=60個まで取得する
)

type IDogrunHandler interface {
	GetDogrunDetail(echo.Context, string) (dto.DogrunDetail, error)
	GetDogrunByID(string)
	GetDogrunTagMst(echo.Context) ([]dto.TagMstRes, error)
	SearchAroundDogruns(echo.Context, dto.SearchAroundRectangleCondition) ([]dto.DogrunLists, error)
	SearchAroundAndTagDogruns(echo.Context, dto.SearchAroundRectangleCondition) ([]dto.DogrunLists, error)
	getBookmarkedDogrunIDs(echo.Context, chan<- []int64)
	GetDogrunPhotoSrc(echo.Context, string, string, string) (string, error)
}

type dogrunHandler struct {
	rest googleplace.IRest
	drr  repository.IDogrunRepository
	bf   facade.IBookmarkFacade
}

func NewDogrunHandler(rest googleplace.IRest, drr repository.IDogrunRepository, bf facade.IBookmarkFacade) IDogrunHandler {
	return &dogrunHandler{rest, drr, bf}
}

// GetDogRunDetailByPlaceId: placeIdでgoogle検索して返す
//
// args:
//   - echo.Context:	コンテキスト
//   - string:	placeID
//
// return:
//   - dto.DogrunDetail:	詳細DTO
//   - error:	エラー
func (h *dogrunHandler) GetDogrunDetail(c echo.Context, placeID string) (dto.DogrunDetail, error) {
	logger := log.GetLogger(c).Sugar()
	//base情報のFieldを使用
	var baseFiled googleplace.IFieldMask = googleplace.BaseField{}
	//place情報の取得
	resG, err := h.rest.GETPlaceInfo(c, placeID, baseFiled)
	if err != nil {
		return dto.DogrunDetail{}, err
	}
	logger.Info("Google Place APIによって、ドッグラン情報の取得成功")

	// JSONデータを構造体にデコード
	var dogrunG googleplace.BaseResource
	err = json.Unmarshal(resG, &dogrunG)
	if err != nil {
		err = errors.NewWRError(nil, "google apiレスポンスの変換に失敗しました。", errors.NewDogrunServerErrorEType())
		logger.Error(err)
		return dto.DogrunDetail{}, err
	}

	if dogrunG.ID == "" {
		return dto.DogrunDetail{}, errors.NewWRError(nil, "指定されたPlaceIdのデータが存在しません。", errors.NewDogrunClientErrorEType())
	}

	//dbから取得
	dogrunD, err := h.drr.GetDogrunByPlaceID(c, placeID)
	if err != nil {
		return dto.DogrunDetail{}, err
	}

	//情報選定
	resDogDetail := resolveDogrunDetail(dogrunG, dogrunD)
	return resDogDetail, nil
}

func (h *dogrunHandler) GetDogrunByID(id string) {
	fmt.Println(h.drr.GetDogrunByID(id))
}

// GetDogrunTagMst: DogrunTagMstのマスターデータの取得
//
// args:
//   - echo.Context:	コンテキスト
//
// return:
//   - []dto.TagMstRes:	マスター情報
//   - error:	エラー
func (h *dogrunHandler) GetDogrunTagMst(c echo.Context) ([]dto.TagMstRes, error) {
	tagMst, err := h.drr.GetTagMst(c)

	mstRes := []dto.TagMstRes{}
	if err != nil {
		return mstRes, err
	}

	for _, m := range tagMst {
		mst := dto.TagMstRes{
			TagID:       m.TagID.Int64,
			TagName:     m.TagName.String,
			Description: m.Description.String,
		}
		mstRes = append(mstRes, mst)
	}

	return mstRes, nil
}

// SearchAroundDogruns: 指定内（長方形）のドッグランをgoogle検索して、DB情報と照合して返す
//
// args:
//   - echo.Context:	コンテキスト
//   - dto.SearchAroundRectangleCondition:	条件
//
// return:
//   - []dto.DogrunLists:	リストDTO
//   - error:	エラー
func (h *dogrunHandler) SearchAroundDogruns(c echo.Context, condition dto.SearchAroundRectangleCondition) ([]dto.DogrunLists, error) {
	logger := log.GetLogger(c).Sugar()
	logger.Debugw("検索条件", "condition", condition)

	payload := googleplace.ConvertReqToSearchTextPayload(condition)

	//ブックマーク済みを並列で取得
	bookmarkedDogrunIDsCH := make(chan []int64)
	go h.getBookmarkedDogrunIDs(c, bookmarkedDogrunIDsCH)

	//base情報のFieldを使用
	var baseFiled googleplace.IFieldMask = googleplace.BaseField{}

	//place情報の取得
	dogrunsG, err := h.searchTextUpToSpecifiedTimes(c, payload, baseFiled)
	if err != nil {
		return nil, err
	}
	logger.Infof("googleレスポンスplace数:%d", len(dogrunsG))
	dogrunGPlaceIDs := []string{}
	for _, dogrunG := range dogrunsG {
		dogrunGPlaceIDs = append(dogrunGPlaceIDs, dogrunG.ID)
	}

	//DBにある指定場所内のドッグランを取得
	dogrunsD, err := h.drr.GetDogrunByRectanglePointerOrPlaceId(c, condition, dogrunGPlaceIDs)
	if err != nil {
		return nil, err
	}
	logger.Infof("DBから取得数:%d", len(dogrunsD))

	//検索結果からレスポンスを作成
	dogrunLists, err := h.integrateDogrunInfos(dogrunsG, dogrunsD)
	logger.Infof("レスポンス件数:%d", len(dogrunLists))
	if err != nil {
		return nil, err
	}

	//dogrunIDがないデータのメンテしてセット
	if err = h.GenerateSetDogrunIDs(c, dogrunLists); err != nil {
		return nil, err
	}

	//ドッグラン情報の過不足フィルター
	dogrunLists = excludeInsufficientDogrunInfo(c, dogrunLists)

	//ブックマーク済みdogrunにフラグ付与
	dogrunLists, err = setIsBookmarked(c, dogrunLists, bookmarkedDogrunIDsCH)
	if err != nil {
		return nil, err
	}

	return dogrunLists, nil
}

// SearchAroundAndTagDogruns: 指定内（長方形）とドッグランタグ条件でDB検索して、返す
// google検索は行わない
//
// args:
//   - echo.Context:	コンテキスト
//   - dto.SearchAroundRectangleCondition:	条件
//
// return:
//   - []dto.DogrunLists:	リストDTO
//   - error:	エラー
func (h *dogrunHandler) SearchAroundAndTagDogruns(c echo.Context, condition dto.SearchAroundRectangleCondition) ([]dto.DogrunLists, error) {

	logger := log.GetLogger(c).Sugar()
	logger.Debugw("検索条件", "condition", condition)

	//ブックマーク済みを並列で取得
	bookmarkedDogrunIDsCH := make(chan []int64)
	go h.getBookmarkedDogrunIDs(c, bookmarkedDogrunIDsCH)

	//DBにある指定場所内のドッグランを取得
	dogrunsD, err := h.drr.GetDogrunByRectanglePointerAndDogrunTags(c, condition)
	if err != nil {
		return nil, err
	}
	logger.Infof("DBから取得数:%d", len(dogrunsD))

	dogrunLists := []dto.DogrunLists{}

	for _, dogrun := range dogrunsD {
		dogrunLists = append(dogrunLists, resolveDogrunListByOnlyDB(dogrun))
	}
	logger.Infof("レスポンス件数:%d", len(dogrunLists))

	//ドッグラン情報の過不足フィルター
	dogrunLists = excludeInsufficientDogrunInfo(c, dogrunLists)

	//ブックマーク済みdogrunにフラグ付与
	dogrunLists, err = setIsBookmarked(c, dogrunLists, bookmarkedDogrunIDsCH)
	if err != nil {
		return nil, err
	}

	return dogrunLists, nil
}

// getBookmarkedDogrunIDs: サブルーチンでログチンユーザーのブックマーク済みDogrunIDを全て取得する
//
// args:
//   - echo.Context:	コンテキスト
//   - chan<- []int64:	送信専用チェネル　ブックマーク済みドッグランIDs
//
// return:
func (h *dogrunHandler) getBookmarkedDogrunIDs(c echo.Context, bookmarkedDogrunIdsCH chan<- []int64) {
	dogrunIDs, err := h.bf.GetAllUserBookmarks(c)
	if err != nil {
		bookmarkedDogrunIdsCH <- nil // 必要に応じてエラー状態を送る
		close(bookmarkedDogrunIdsCH) // チャネルを閉じる
		return
	}
	bookmarkedDogrunIdsCH <- dogrunIDs
	close(bookmarkedDogrunIdsCH) // チャネルを閉じる
}

// setIsBookmarked: チャネルからブックマーク済みDogrunにフラグをセットする
//
// args:
//   - echo.Context:	コンテキスト
//   - []dto.DogrunLists:	dogruns
//   - <-chan []int64:	受信専用チェネル　ブックマーク済みドッグランIDs
//
// return:
func setIsBookmarked(c echo.Context, dogrunLists []dto.DogrunLists, bookmarkedDogrunIDsCH <-chan []int64) ([]dto.DogrunLists, error) {
	logger := log.GetLogger(c).Sugar()
	// ブックマーク済みdogrunにフラグ付与
	bookmarkedDogrunIDs := <-bookmarkedDogrunIDsCH
	if bookmarkedDogrunIDs == nil {
		err := errors.NewWRError(nil, "非同期でのドッグランのブックーマーク取得に失敗しました。", errors.NewDogrunServerErrorEType())
		logger.Error(err)
		return nil, err
	}
	// mapに変換
	bookmarkedDogrunIDMap := util.ConvertSliceToMap(bookmarkedDogrunIDs, func(i int64) int64 { return i })
	for i := range dogrunLists {
		if _, exist := bookmarkedDogrunIDMap[int64(dogrunLists[i].DogrunID)]; exist {
			dogrunLists[i].IsBookmarked = true
		}
	}
	return dogrunLists, nil
}

/*
ドッグランのgoogle画像をnameからsource用のURLを取得する
*/
func (h *dogrunHandler) GetDogrunPhotoSrc(c echo.Context, name, widthPx, heightPx string) (string, error) {
	logger := log.GetLogger(c).Sugar()

	res, err := h.rest.GETPhotoByName(c, name, widthPx, heightPx)

	if err != nil {
		return "", err
	}

	var photo googleplace.PhotoMediaResource
	err = json.Unmarshal(res, &photo)
	if err != nil {
		err = errors.NewWRError(nil, "google apiレスポンスの変換に失敗しました。", errors.NewDogrunServerErrorEType())
		logger.Error(err)
		return "", err
	}

	return photo.PhotoUri, nil
}

/*
Google情報とDB情報から、ドッグラン詳細情報を作成
基本的に、DB情報をドッグランマネージャーからの手動更新がある前提で、優先情報とする
*/
func resolveDogrunDetail(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) dto.DogrunDetail {

	if dogrunD.IsEmpty() && dogrunG.IsNotEmpty() {
		return resolveDogrunDetailByOnlyGoogle(dogrunG)
	} else if dogrunD.IsNotEmpty() && dogrunG.IsEmpty() {
		return resolveDogrunDetailByOnlyDB(dogrunD)
	}

	var dogrunManager int64
	if dogrunD.DogrunManagerID.Valid {
		dogrunManager = dogrunD.DogrunManagerID.Int64
	}

	return dto.DogrunDetail{
		DogrunID:        dogrunD.DogrunID.Int64,
		DogrunManagerID: dogrunManager,
		PlaceId:         dogrunG.ID,
		Name:            util.ChooseStringValidValue(dogrunD.Name, dogrunG.DisplayName.Text),
		Address:         resolveDogrunAddress(dogrunG, dogrunD),
		Location: dto.Location{
			Latitude:  util.ChooseFloat64ValidValue(dogrunD.Latitude, dogrunG.Location.Latitude),
			Longitude: util.ChooseFloat64ValidValue(dogrunD.Longitude, dogrunG.Location.Longitude),
		},
		BusinessStatus: dogrunG.BusinessStatus,
		NowOpen:        resolveNowOpening(dogrunG, dogrunD),
		BusinessHour: dto.BusinessHour{
			Regular: resolveRegularBusinessHour(dogrunG, dogrunD),
			Special: resolveSpecialBusinessHour(dogrunD),
		},
		Description:     util.ChooseStringValidValue(dogrunD.Description, dogrunG.Summary.Text),
		GoogleRating:    dogrunG.Rating,
		UserRatingCount: dogrunG.UserRatingCount,
		DogrunTags:      resolveDogrunTagInfo(dogrunD), // ドッグランタグ情報
		CreateAt:        &dogrunD.CreateAt.Time,
		UpdateAt:        &dogrunD.UpdateAt.Time,
	}

}

/*
DBにデータがない場合、google情報のみでドッグラン詳細情報を作成する
*/
func resolveDogrunDetailByOnlyGoogle(dogrunG googleplace.BaseResource) dto.DogrunDetail {
	var emptyDogrunD model.Dogrun
	return dto.DogrunDetail{
		PlaceId: dogrunG.ID,
		Name:    dogrunG.DisplayName.Text,
		Address: resolveDogrunAddress(dogrunG, emptyDogrunD),
		Location: dto.Location{
			Latitude:  dogrunG.Location.Latitude,
			Longitude: dogrunG.Location.Longitude,
		},
		BusinessStatus: dogrunG.BusinessStatus,
		NowOpen:        resolveNowOpening(dogrunG, emptyDogrunD),
		BusinessHour: dto.BusinessHour{
			Regular: resolveRegularBusinessHour(dogrunG, emptyDogrunD),
			Special: resolveSpecialBusinessHour(emptyDogrunD),
		},
		Description:     dogrunG.Summary.Text,
		GoogleRating:    dogrunG.Rating,
		UserRatingCount: dogrunG.UserRatingCount,
	}
}

func resolveDogrunDetailByOnlyDB(dogrunD model.Dogrun) dto.DogrunDetail {

	var emptyDogrunG googleplace.BaseResource

	return dto.DogrunDetail{
		DogrunID:        dogrunD.DogrunID.Int64,
		DogrunManagerID: dogrunD.DogrunManagerID.Int64,
		PlaceId:         dogrunD.PlaceId.String,
		Name:            dogrunD.Name.String,
		Address:         resolveDogrunAddress(emptyDogrunG, dogrunD),
		Location: dto.Location{
			Latitude:  dogrunD.Latitude.Float64,
			Longitude: dogrunD.Longitude.Float64,
		},
		NowOpen: resolveNowOpening(emptyDogrunG, dogrunD),
		BusinessHour: dto.BusinessHour{
			Regular: resolveRegularBusinessHour(emptyDogrunG, dogrunD),
			Special: resolveSpecialBusinessHour(dogrunD),
		},
		Description: dogrunD.Description.String,
		DogrunTags:  resolveDogrunTagInfo(dogrunD), // ドッグランタグ情報
		CreateAt:    &dogrunD.CreateAt.Time,
		UpdateAt:    &dogrunD.UpdateAt.Time,
	}
}

/*
DBからドッグランタグ情報を取得
*/
func resolveDogrunTagInfo(dogrunD model.Dogrun) []int64 {

	if dogrunD.IsDogrunTagEmpty() {
		return nil
	}

	dogrunTag := dogrunD.DogrunTags

	dogrunTagIds := []int64{}
	for _, v := range dogrunTag {
		dogrunTagIds = append(dogrunTagIds, v.TagID.Int64)
	}
	return dogrunTagIds
}

/*
住所情報の選定
*/
func resolveDogrunAddress(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) dto.Address {

	var gPostCodeComponent googleplace.AddressComponent
	for _, v := range dogrunG.AddressComponents {
		if slices.Contains(v.Types, googleplace.ADDRESSCOMPONENT_TYPES_POSTAL_CODE) {
			gPostCodeComponent = v
			break
		}
	}
	var address string
	var postCode string

	if dogrunD.IsNotEmpty() && dogrunG.IsNotEmpty() { //両方にある場合
		address = util.ChooseStringValidValue(dogrunD.Address, dogrunG.ShortFormattedAddress)
		postCode = util.ChooseStringValidValue(dogrunD.PostCode, gPostCodeComponent.LongText)
	} else if dogrunD.IsNotEmpty() { //DBにのみある場合
		address = dogrunD.Address.String
		postCode = dogrunD.PostCode.String
	} else if dogrunG.IsNotEmpty() { //google側にのみ
		address = dogrunG.ShortFormattedAddress
		postCode = gPostCodeComponent.LongText
	}

	return dto.Address{PostCode: postCode, Address: address}
}

/*
営業時間から、現在が営業中かを判定
*/
func resolveNowOpening(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) bool {

	if dogrunD.IsEmpty() && dogrunG.IsNotEmpty() { //DB情報がない時
		return dogrunG.OpeningHours.OpenNow
	}

	now := time.Now()

	//DBより、今日の曜日の通常営業時間情報を取得
	regularBusinessHour := dogrunD.FetchTargetRegularBusinessHour(int(now.Weekday()))
	todaySpecialBusinesshour := dogrunD.FetchTargetDateSpecialBusinessHour(now)

	var nowOpen bool

	if todaySpecialBusinesshour.IsValid() {
		//今日の特別営業日データがある場合、
		if todaySpecialBusinesshour.IsAllDay.Bool { //24時間営業の場合、true
			nowOpen = true
		} else if todaySpecialBusinesshour.IsClosed.Bool { //特別定休日の場、false
			nowOpen = false
		} else {
			//その他は開始時間/終了時間より判定
			openTimeStr := todaySpecialBusinesshour.OpenTime.String
			closeTimeStr := todaySpecialBusinesshour.CloseTime.String
			nowOpen = DetermineIsOpen(now, util.ParseStrToTime(openTimeStr), util.ParseStrToTime(closeTimeStr))
		}
	} else if regularBusinessHour.IsValid() {
		if regularBusinessHour.IsClosed.Bool {
			nowOpen = false
		} else if regularBusinessHour.IsAllDay.Bool {
			nowOpen = true
		} else if !regularBusinessHour.OpenTime.Valid || !regularBusinessHour.CloseTime.Valid {
			//DB情報がどちらかが無効ならfalse
			nowOpen = false
		} else {
			//通常営業時間より判定
			openTimeStr := regularBusinessHour.OpenTime.String
			closeTimeStr := regularBusinessHour.CloseTime.String
			nowOpen = DetermineIsOpen(now, util.ParseStrToTime(openTimeStr), util.ParseStrToTime(closeTimeStr))
		}
	}

	return nowOpen
}

func DetermineIsOpen(now, openTime, closeTime time.Time) bool {
	// 時間部分だけを取り出しては、他は統一
	openTime = time.Date(now.Year(), now.Month(), now.Day(), openTime.Hour(), openTime.Minute(), 00, 0, time.UTC)
	closeTime = time.Date(now.Year(), now.Month(), now.Day(), closeTime.Hour(), closeTime.Minute(), 00, 0, time.UTC)
	// 終了時間が開始時間よりも前の場合、終了時間を次の日に設定
	if closeTime.Before(openTime) {
		closeTime = closeTime.Add(24 * time.Hour)
		if now.Before(openTime) {
			now = now.Add(24 * time.Hour)
		}
	}

	return now.After(openTime) && now.Before(closeTime)
}

/*
通常営業時間の判定
*/
func resolveRegularBusinessHour(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) dto.RegularBusinessHour {
	var businessHoursG dto.RegularBusinessHour

	//まずgoogle情報をまとめる
	//google情報は、periodsにない曜日は定休日なので、それを考慮し0~6でfor文まわす
	for i := 0; i < 7; i++ {
		openPeriod, closePeriod := dogrunG.OpeningHours.FetchTargetPeriod(i)
		isHoliday := openPeriod == nil && closePeriod == nil
		var openTime, closeTime string
		var isAllDay bool
		if !isHoliday {
			openTime = openPeriod.FormatTime()
			closeTime = closePeriod.FormatTime()
			isAllDay = openTime == closeTime
		}
		businessTime := dto.DayBusinessTime{
			OpenTime:  openTime,
			CloseTime: closeTime,
			IsAllDay:  isAllDay,
			IsHoliday: isHoliday,
		}
		attachRegularBusinessTime(&businessHoursG, businessTime, i)
	}
	//google情報が空でなくて、DB情報がなければgoogle情報を返す
	if dogrunG.OpeningHours.IsNotEmpty() && dogrunD.IsRegularBusinessHoursEmpty() {
		return businessHoursG
	}

	//次にDB情報をまとめる
	var businessHoursD dto.RegularBusinessHour
	for i := 0; i < 7; i++ {
		targetBusinessHour := dogrunD.FetchTargetRegularBusinessHour(i)
		openTime, closeTime := targetBusinessHour.FormatTime()
		businessTime := dto.DayBusinessTime{
			OpenTime:  openTime,
			CloseTime: closeTime,
			IsAllDay:  targetBusinessHour.IsAllDay.Bool,
			IsHoliday: targetBusinessHour.IsClosed.Bool,
		}
		attachRegularBusinessTime(&businessHoursD, businessTime, i)
	}

	return businessHoursD
}

/*
特別営業時間の整理
*/
func resolveSpecialBusinessHour(dogrunD model.Dogrun) []dto.SpecialBusinessHour {
	if dogrunD.IsSpecialBusinessHoursEmpty() {
		return []dto.SpecialBusinessHour{}
	}

	var specialBusinessHours []dto.SpecialBusinessHour
	for _, v := range dogrunD.SpecialBusinessHours {
		if v.IsValid() {
			openTime, closeTime := v.FormatTime()
			specialBusinessHour := dto.SpecialBusinessHour{
				Date: v.FormatDate(),
				DayBusinessTime: dto.DayBusinessTime{
					OpenTime:  openTime,
					CloseTime: closeTime,
					IsAllDay:  v.IsAllDay.Bool,
					IsHoliday: v.IsClosed.Bool,
				},
			}
			specialBusinessHours = append(specialBusinessHours, specialBusinessHour)
		}
	}

	return specialBusinessHours
}

/*
曜日(数値)ごとに、営業時間をDTOに代入していく
*/
func attachRegularBusinessTime(businessHours *dto.RegularBusinessHour, businessTime dto.DayBusinessTime, day int) {
	switch day {
	case 0:
		businessHours.Sunday = businessTime
	case 1:
		businessHours.Monday = businessTime
	case 2:
		businessHours.Tuesday = businessTime
	case 3:
		businessHours.Wednesday = businessTime
	case 4:
		businessHours.Thursday = businessTime
	case 5:
		businessHours.Friday = businessTime
	case 6:
		businessHours.Saturday = businessTime
	}
}

/*
searchTextを指定上限回数まで実行する
条件：nextPageTokenが含まれている && リクエスト上限回数を超えていないこと
*/
func (h *dogrunHandler) searchTextUpToSpecifiedTimes(c echo.Context, payload googleplace.SearchTextPayLoad, fields googleplace.IFieldMask) ([]googleplace.BaseResource, error) {
	logger := log.GetLogger(c).Sugar()
	var dogruns []googleplace.BaseResource

	var times int
	for {
		times++
		res, err := h.rest.POSTSearchText(c, payload, fields)
		if err != nil {
			return nil, err
		}
		// JSONデータを構造体にデコード
		searchTextRes := &googleplace.SearchTextBaseResource{}
		err = json.Unmarshal(res, searchTextRes)
		if err != nil {
			err = errors.NewWRError(nil, "google apiレスポンスの変換に失敗しました。", errors.NewDogrunServerErrorEType())
			logger.Error(err)
			return nil, err
		}
		logger.Infow(fmt.Sprintf("レスポンス-%d", times), "response", searchTextRes)
		dogruns = append(dogruns, searchTextRes.Places...)

		//nextPageTokenがない時 or リクエスト上限に達した時
		if searchTextRes.NextPageToken == nil || times > SEARCH_TEXT_MAX_REQUEST_TIMES {
			break
		}

		payload.PageToken = *searchTextRes.NextPageToken
	}

	return dogruns, nil
}

/*
検索結果をもとに、レスポンス用のDTOを作成
placeIdで、両方にあるデータと、DBにのみあるデータ等で分けて、それぞれ統合する
*/
func (h *dogrunHandler) integrateDogrunInfos(dogrunsG []googleplace.BaseResource, dogrunsD []model.Dogrun) ([]dto.DogrunLists, error) {
	//google情報からplaceIdをkeyにmapにまとめる
	dogrunsGWithPlaceID := make(map[string]googleplace.BaseResource, len(dogrunsG))
	for _, dogrunG := range dogrunsG {
		dogrunsGWithPlaceID[dogrunG.ID] = dogrunG
	}

	//DB情報からplaceIdがあるデータのみ、mapにまとめる
	dogrunsDWithPlaceID := make(map[string]model.Dogrun)
	//placeIdがないもののみでまとめる
	var dogrunDWithoutPlaceIdS []model.Dogrun
	for _, dogrunD := range dogrunsD {
		if dogrunD.PlaceId.Valid {
			dogrunsDWithPlaceID[dogrunD.PlaceId.String] = dogrunD
		} else {
			dogrunDWithoutPlaceIdS = append(dogrunDWithoutPlaceIdS, dogrunD)
		}
	}

	dogrunLists := []dto.DogrunLists{}

	//両方にplaceIdがある情報をDTOにつめる
	for placeId, dogrunGValue := range dogrunsGWithPlaceID {
		dogrunDValue, existDogrunD := dogrunsDWithPlaceID[placeId]
		if existDogrunD {
			//DBにもある場合、両方からデータの選別してセット
			dogrunLists = append(dogrunLists, resolveDogrunList(dogrunGValue, dogrunDValue))
			//DogrunsDから削除
			delete(dogrunsDWithPlaceID, placeId)
		} else {
			//google側にしかない場合
			//レスポンス整形してセット
			dogrunLists = append(dogrunLists, resolveDogrunListByOnlyGoogle(dogrunGValue))
		}
	}

	//placeIdはあるが、google側にないものをDTOにつめる
	for _, dogrunDValue := range dogrunsDWithPlaceID {
		dogrunLists = append(dogrunLists, resolveDogrunListByOnlyDB(dogrunDValue))
	}

	//placeIdがないDBのみのデータをDTOにつめる
	for _, dogrunDValue := range dogrunDWithoutPlaceIdS {
		dogrunLists = append(dogrunLists, resolveDogrunListByOnlyDB(dogrunDValue))
	}

	return dogrunLists, nil
}

/*
Google情報とDB情報から、ドッグラン一覧情報を作成
基本的に、DB情報をドッグランマネージャーからの手動更新がある前提で、優先情報とする
*/
func resolveDogrunList(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) dto.DogrunLists {
	return dto.DogrunLists{
		DogrunID: dogrunD.DogrunID.Int64,
		PlaceId:  dogrunG.ID,
		Name:     util.ChooseStringValidValue(dogrunD.Name, dogrunG.DisplayName.Text),
		Address:  resolveDogrunAddress(dogrunG, dogrunD),
		Location: dto.Location{
			Latitude:  util.ChooseFloat64ValidValue(dogrunD.Latitude, dogrunG.Location.Latitude),
			Longitude: util.ChooseFloat64ValidValue(dogrunD.Longitude, dogrunG.Location.Longitude),
		},
		BusinessStatus:    dogrunG.BusinessStatus,
		NowOpen:           resolveNowOpening(dogrunG, dogrunD),
		ToadyBusinessHour: resolveTodayBusinessHour(dogrunG, dogrunD),
		Description:       util.ChooseStringValidValue(dogrunD.Description, dogrunG.Summary.Text),
		GoogleRating:      dogrunG.Rating,
		UserRatingCount:   dogrunG.UserRatingCount,
		Photos:            resolvePlacePhotos(dogrunG),
		DogrunTags:        resolveDogrunTagInfo(dogrunD), // ドッグランタグ情報
		IsManaged:         true,
	}

}

/*
DBにデータがない場合、google情報のみでドッグラン一覧情報を作成する
*/
func resolveDogrunListByOnlyGoogle(dogrunG googleplace.BaseResource) dto.DogrunLists {
	var emptyDogrunD model.Dogrun

	return dto.DogrunLists{
		PlaceId: dogrunG.ID,
		Name:    dogrunG.DisplayName.Text,
		Address: resolveDogrunAddress(dogrunG, emptyDogrunD),
		Location: dto.Location{
			Latitude:  dogrunG.Location.Latitude,
			Longitude: dogrunG.Location.Longitude,
		},
		BusinessStatus:    dogrunG.BusinessStatus,
		NowOpen:           resolveNowOpening(dogrunG, emptyDogrunD),
		ToadyBusinessHour: resolveTodayBusinessHour(dogrunG, emptyDogrunD),
		Description:       dogrunG.Summary.Text,
		GoogleRating:      dogrunG.Rating,
		UserRatingCount:   dogrunG.UserRatingCount,
		Photos:            resolvePlacePhotos(dogrunG),
		IsManaged:         false,
	}

}

/*
google側にデータがない場合、DB情報のみでドッグラン一覧情報を作成する
*/
func resolveDogrunListByOnlyDB(dogrunD model.Dogrun) dto.DogrunLists {
	var emptyDogrunG googleplace.BaseResource
	return dto.DogrunLists{
		DogrunID: dogrunD.DogrunID.Int64,
		PlaceId:  dogrunD.PlaceId.String,
		Name:     dogrunD.Name.String,
		Address:  resolveDogrunAddress(emptyDogrunG, dogrunD),
		Location: dto.Location{
			Latitude:  dogrunD.Latitude.Float64,
			Longitude: dogrunD.Longitude.Float64,
		},
		NowOpen:           resolveNowOpening(emptyDogrunG, dogrunD),
		ToadyBusinessHour: resolveTodayBusinessHour(emptyDogrunG, dogrunD),
		Description:       dogrunD.Description.String,
		DogrunTags:        resolveDogrunTagInfo(dogrunD), // ドッグランタグ情報
		IsManaged:         true,
	}

}

/*
今日の営業時間のみの情報を判定
*/
func resolveTodayBusinessHour(dogrunG googleplace.BaseResource, dogrunD model.Dogrun) dto.DayBusinessTime {
	//今日の曜日取得
	todayWeekday := time.Now().Weekday()

	openPeriod, closePeriod := dogrunG.OpeningHours.FetchTargetPeriod(int(todayWeekday))
	isHoliday := openPeriod == nil && closePeriod == nil
	var openTimeG, closeTimeG string
	var isAllDay bool
	if !isHoliday {
		openTimeG = openPeriod.FormatTime()
		closeTimeG = closePeriod.FormatTime()
		isAllDay = openTimeG == closeTimeG
	}
	todayBusinessTimeG := dto.DayBusinessTime{
		OpenTime:  openTimeG,
		CloseTime: closeTimeG,
		IsAllDay:  isAllDay,
		IsHoliday: isHoliday,
	}
	//google情報が空でなくて、DB情報がなければgoogle情報を返す
	if dogrunG.OpeningHours.IsNotEmpty() && dogrunD.IsRegularBusinessHoursEmpty() {
		return todayBusinessTimeG
	}

	targetBusinessHour := dogrunD.FetchTargetRegularBusinessHour(int(todayWeekday))
	openTime, closeTime := targetBusinessHour.FormatTime()
	todayBusinessTimeD := dto.DayBusinessTime{
		OpenTime:  openTime,
		CloseTime: closeTime,
		IsAllDay:  targetBusinessHour.IsAllDay.Bool,
		IsHoliday: targetBusinessHour.IsClosed.Bool,
	}

	return todayBusinessTimeD
}

/*
googleの社員情報をレスポンスに整形
*/
func resolvePlacePhotos(dogrunG googleplace.BaseResource) []dto.PhotoInfo {
	var photos []dto.PhotoInfo

	for _, photo := range dogrunG.Photos {
		photoInfo := dto.PhotoInfo{
			PhotoKey: photo.Name,
			HeightPx: photo.HeightPx,
			WidthPx:  photo.WidthPx,
		}
		photos = append(photos, photoInfo)
	}

	return photos
}

// GenerateSetDogrunIDs: dogrunIDがないデータに対して、dogrunsテーブルに登録し、IDをdtoにセットする
//
// args:
//   - echo.Context:	コンテキスト
//   - []dto.DogrunLists:	dogrunIDメンテを行う対象のdto
//
// return:
//   - error:	エラー
func (h *dogrunHandler) GenerateSetDogrunIDs(c echo.Context, dogrunLists []dto.DogrunLists) error {
	for i := range dogrunLists {
		if dogrunLists[i].DogrunID == 0 {
			//id発行
			dogrunID, err := h.persistenceDogrunPlaceId(c, dogrunLists[i].PlaceId)
			if err != nil {
				return err
			}
			dogrunLists[i].DogrunID = dogrunID
		}
	}
	return nil
}

// persistenceDogrunPlaceId: DBにないplaceIdをDBへ保存して、PKを発行させる
//
// args:
//   - *dogrunHandler: h handler
//   - echo.Context: c	echo.Context
//   - string: placeId	DBへ登録するplaceId
//
// return:
//   - int:	dogrunテーブルのPK
//   - error:	エラー
func (h *dogrunHandler) persistenceDogrunPlaceId(c echo.Context, placeId string) (int64, error) {
	logger := log.GetLogger(c).Sugar()

	logger.Infof("placeId\"%s\"がDBに存在しないため、レコードを作成", placeId)
	id, err := h.drr.RegistDogrunPlaceId(c, placeId)
	if err != nil {
		logger.Error(err)
		err := errors.NewWRError(err, "placeIdのDB保存処理に失敗", errors.NewDogrunServerErrorEType())
		return 0, err
	}
	logger.Infof("PKの生成  %s->%s", placeId, id)
	return id, nil
}

// excludeIncompleteDogrunInfo:
//
// args:
//   - []dto.Dogrun:	チェック対象のドッグランDB情報
//
// return:
//   - []model.Dogrun:	チェック済みドッグラン情報
func excludeInsufficientDogrunInfo(c echo.Context, dogrunsDParam []dto.DogrunLists) []dto.DogrunLists {
	logger := log.GetLogger(c).Sugar()
	dogruns := []dto.DogrunLists{}
	for _, dogrun := range dogrunsDParam {
		if dogrun.IsSufficientInfo() {
			dogruns = append(dogruns, dogrun)
		} else {
			logger.Infof("ドッグラン:%d を情報不足として、dtoから除外", dogrun.DogrunID)
		}
	}

	return dogruns
}
