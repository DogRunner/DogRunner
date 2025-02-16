package dto

import (
	"time"
)

// ドッグラン詳細画面での表示情報
type DogrunDetail struct {
	DogrunID        int64        `json:"dogrunId,omitempty"`
	DogrunManagerID int64        `json:"dogrunManagerId,omitempty"`
	PlaceId         string       `json:"placeId,omitempty"`
	Name            string       `json:"name"`
	Address         Address      `json:"address"`
	Location        Location     `json:"location"`
	BusinessStatus  string       `json:"businessStatus,omitempty"`
	NowOpen         bool         `json:"nowOpen"`
	BusinessHour    BusinessHour `json:"businessHour"`
	Description     string       `json:"description,omitempty"`
	GoogleRating    float32      `json:"googleRating,omitempty"`
	UserRatingCount int          `json:"userRatingCount,omitempty"`
	DogrunTags      []int64      `json:"dogrunTagId,omitempty"`
	CreateAt        *time.Time   `json:"createAt,omitempty"`
	UpdateAt        *time.Time   `json:"updateAt,omitempty"`
}

// ドッグラン一覧での表示情報
type DogrunLists struct {
	DogrunID          int64           `json:"dogrunId,omitempty"`
	PlaceId           string          `json:"placeId,omitempty"`
	Name              string          `json:"name"`
	Address           Address         `json:"address"`
	Location          Location        `json:"location"`
	BusinessStatus    string          `json:"businessStatus,omitempty"`
	NowOpen           bool            `json:"nowOpen"`
	ToadyBusinessHour DayBusinessTime `json:"toadyBusinessHour"`
	Description       string          `json:"description,omitempty"`
	GoogleRating      float32         `json:"googleRating,omitempty"`
	UserRatingCount   int             `json:"userRatingCount,omitempty"`
	DogrunTags        []int64         `json:"dogrunTagId,omitempty"`
	Photos            []PhotoInfo     `json:"photos,omitempty"`
	IsBookmarked      bool            `json:"isBookmarked"`
	IsManaged         bool            `json:"isManaged"`
}

/*
データの過不足チェック
Dogrun情報としての最低限必要情報のチェック
*/
func (d *DogrunLists) IsSufficientInfo() bool {
	if d.Name == "" {
		return false
	}
	if d.Address.PostCode == "" || d.Address.Address == "" {
		return false
	}
	if d.Location.Latitude == 0 {
		return false
	}
	if d.Location.Longitude == 0 {
		return false
	}

	return true
}

// 営業日情報
type BusinessHour struct {
	Regular RegularBusinessHour   `json:"regular"`
	Special []SpecialBusinessHour `json:"special,omitempty"`
}

// 通常営業日情報
type RegularBusinessHour struct {
	Sunday    DayBusinessTime `json:"0,omitempty"`
	Monday    DayBusinessTime `json:"1,omitempty"`
	Tuesday   DayBusinessTime `json:"2,omitempty"`
	Wednesday DayBusinessTime `json:"3,omitempty"`
	Thursday  DayBusinessTime `json:"4,omitempty"`
	Friday    DayBusinessTime `json:"5,omitempty"`
	Saturday  DayBusinessTime `json:"6,omitempty"`
}

type DayBusinessTime struct {
	OpenTime  string `json:"openTime"`
	CloseTime string `json:"closeTime"`
	IsAllDay  bool   `json:"isAllDay"`
	IsHoliday bool   `json:"isHoliday"`
}

// 特別営業日情報
type SpecialBusinessHour struct {
	Date string `json:"date"`
	DayBusinessTime
}

type PhotoInfo struct {
	PhotoKey string `json:"photoKey"`
	WidthPx  uint   `json:"widthPx"`
	HeightPx uint   `json:"heightPx"`
}

// 軽度・緯度情報
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// 住所情報
type Address struct {
	PostCode string `json:"postcode"`
	Address  string `json:"address"`
}

// dogrunTagマスター情報
type TagMstRes struct {
	TagID       int64  `json:"tagId"`
	TagName     string `json:"tagName"`
	Description string `json:"description"`
}
