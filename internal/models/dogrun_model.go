package model

import (
	"database/sql"
	"time"
)

const (
	EmailField       = "email"
	PhoneNumberField = "phone_number"
)

type Dogrun struct {
	DogrunID        sql.NullInt64   `gorm:"primaryKey;column:dogrun_id;autoIncrement"`
	DogrunManagerID sql.NullInt64   `gorm:"column:dogrun_manager_id;foreignKey:DogrunManagerID"`
	PlaceId         sql.NullString  `gorm:"size:256;column:place_id"`
	Name            sql.NullString  `gorm:"size:256;column:name"`
	Address         sql.NullString  `gorm:"size:256;column:address"`
	PostCode        sql.NullString  `gorm:"size:8;column:postcode"`
	Latitude        sql.NullFloat64 `gorm:"column:latitude"`
	Longitude       sql.NullFloat64 `gorm:"column:longitude"`
	Description     sql.NullString  `gorm:"type:text;column:description"`
	IsManaged       sql.NullBool    `gorm:"column:is_managed"`
	CreateAt        sql.NullTime    `gorm:"column:reg_at;not null;autoCreateTime"`
	UpdateAt        sql.NullTime    `gorm:"column:upd_at;not null;autoUpdateTime"`

	//リレーション
	DogrunTags           []DogrunTag           `gorm:"foreignKey:DogrunID;references:DogrunID"`
	RegularBusinessHours []RegularBusinessHour `gorm:"foreignKey:DogrunID;references:DogrunID"`
	SpecialBusinessHours []SpecialBusinessHour `gorm:"foreignKey:DogrunID;references:DogrunID"`
}

/*
dogrunが空かの判定
*/
func (d *Dogrun) IsEmpty() bool {
	return !d.DogrunID.Valid
}

/*
dogrunが空でないかの判定
*/
func (d *Dogrun) IsNotEmpty() bool {
	return !d.IsEmpty()
}

/*
dogrunタグ情報が空かの判定
*/
func (d *Dogrun) IsDogrunTagEmpty() bool {
	return len(d.DogrunTags) == 0
}

/*
dogrunタグ情報が空ではないかの判定
*/
func (d *Dogrun) IsDogrunTagNotEmpty() bool {
	return !d.IsDogrunTagEmpty()
}

/*
通常営業時間情報が空かの判定
*/
func (d *Dogrun) IsRegularBusinessHoursEmpty() bool {
	return len(d.RegularBusinessHours) == 0
}

/*
通常営業時間情報が空かの判定
*/
func (d *Dogrun) IsRegularBusinessHoursNotEmpty() bool {
	return !d.IsRegularBusinessHoursEmpty()
}

/*
特別営業時間情報が空かの判定
*/
func (d *Dogrun) IsSpecialBusinessHoursEmpty() bool {
	return len(d.SpecialBusinessHours) == 0
}

/*
特別営業時間情報が空かの判定
*/
func (d *Dogrun) IsSpecialBusinessHoursNotEmpty() bool {
	return !d.IsSpecialBusinessHoursEmpty()
}

/*
対象のドッグランの通常営業時時間データから、指定されたの曜日(数値:0~6)の営業時間データを返す
*/
func (d *Dogrun) FetchTargetRegularBusinessHour(day int) RegularBusinessHour {
	for _, v := range d.RegularBusinessHours {
		if day == int(v.Day.Int64) {
			return v
		}
	}
	return RegularBusinessHour{}
}

/*
対象のドッグランの特別営業時時間データから、指定されたの日にちの営業時間データを返す
*/
func (d *Dogrun) FetchTargetDateSpecialBusinessHour(date time.Time) SpecialBusinessHour {
	for _, v := range d.SpecialBusinessHours {
		if v.IsValid() && date == v.Date.Time {
			return v
		}
	}
	return SpecialBusinessHour{}
}

type RegularBusinessHour struct {
	RegularBusinessHourID sql.NullInt64  `gorm:"primaryKey;column:regular_business_hours_id;autoIncrement"`
	DogrunID              sql.NullInt64  `gorm:"not null;column:dogrun_id"`
	Day                   sql.NullInt64  `gorm:"not null;column:day"`             // 曜日（0: 日曜日, 1: 月曜日,...）
	OpenTime              sql.NullString `gorm:"column:open_time"`                // 開店時間
	CloseTime             sql.NullString `gorm:"column:close_time"`               // 閉店時間
	IsAllDay              sql.NullBool   `gorm:"default:false;column:is_all_day"` // 24時間営業フラグ（trueの場合。opentime, closetimeより優先されるフラグ）
	IsClosed              sql.NullBool   `gorm:"default:false;column:is_closed"`  // 定休日フラグ（trueの場合。opentime, closetimeより優先されるフラグ）
	CreatedAt             sql.NullTime   `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt             sql.NullTime   `gorm:"column:updated_at;autoUpdateTime"`
}

/*
RegularBusinessHourの有効チェック
*/
func (r *RegularBusinessHour) IsValid() bool {
	return r.RegularBusinessHourID.Valid && r.DogrunID.Valid && r.Day.Valid
}

/*
RegularBusinessHourの営業開始時間/終了時間をHH:mm(string)にして返す
*/
func (r *RegularBusinessHour) FormatTime() (string, string) {
	openTime, closeTime := "不明", "不明"
	if r.OpenTime.Valid {
		openTime = r.OpenTime.String
	}

	if r.CloseTime.Valid {
		closeTime = r.CloseTime.String
	}

	return openTime, closeTime
}

type SpecialBusinessHour struct {
	SpecialBusinessHourID sql.NullInt64  `gorm:"primaryKey;column:special_business_hours_id;autoIncrement"`
	DogrunID              sql.NullInt64  `gorm:"not null;column:dogrun_id"`
	Date                  sql.NullTime   `gorm:"not null;column:date"`            // 特別営業時間の日付
	OpenTime              sql.NullString `gorm:"column:open_time"`                // 特別営業時間の開店時間
	CloseTime             sql.NullString `gorm:"column:close_time"`               // 特別営業時間の閉店時間
	IsAllDay              sql.NullBool   `gorm:"default:false;column:is_all_day"` // 24時間営業フラグ（trueの場合。opentime, closetimeより優先されるフラグ）
	IsClosed              sql.NullBool   `gorm:"default:false;column:is_closed"`  // 特別定休日フラグtrueの場合。opentime, closetimeより優先されるフラグ）
	CreatedAt             sql.NullTime   `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt             sql.NullTime   `gorm:"column:updated_at;autoUpdateTime"`
}

/*
SpecialBusinessHourが有効なデータか
*/
func (r *SpecialBusinessHour) IsValid() bool {
	return r.SpecialBusinessHourID.Valid && r.Date.Valid
}

/*
SpecialBusinessHourの営業開始時間/終了時間をHH:mm(string)にして返す
*/
func (r *SpecialBusinessHour) FormatTime() (string, string) {
	openTime, closeTime := "不明", "不明"
	if r.OpenTime.Valid {
		openTime = r.OpenTime.String
	}

	if r.CloseTime.Valid {
		closeTime = r.CloseTime.String
	}

	return openTime, closeTime
}

/*
日付を"yyyy/MM/dd"形式で取得する
*/
func (r *SpecialBusinessHour) FormatDate() string {
	if !r.Date.Valid {
		return "不明" // 値がNULLの場合
	}
	// 有効な場合は "yyyy/MM/dd" 形式にフォーマット
	return r.Date.Time.Format("2006/01/02")
}

type DogrunTag struct {
	DogrunTagID sql.NullInt64 `gorm:"primaryKey;column:dogrun_tag_id;autoIncrement"`
	DogrunID    sql.NullInt64 `gorm:"column:dogrun_id;not null"`
	TagID       sql.NullInt64 `gorm:"column:tag_id;not null"`
}

type TagMst struct {
	TagID       sql.NullInt64  `gorm:"primaryKey;column:tag_id;autoIncrement"`
	TagName     sql.NullString `gorm:"size:64;column:tag_name;not null"`
	Description sql.NullString `gorm:"type:text;column:description"`
}

// GORMにテーブル名を指定
func (TagMst) TableName() string {
	return "tag_mst"
}

type DogrunImage struct {
	DogrunImageID int64         `gorm:"primaryKey;column:dogrun_image_id;autoIncrement"`
	DogrunID      int64         `gorm:"column:dogrun_id;not null"`
	Image         string        `gorm:"type:text;column:image;not null"`
	SortOrder     sql.NullInt64 `gorm:"column:sort_order"`
	UploadAt      sql.NullTime  `gorm:"column:upload_at"`

	//リレーション
	Dogrun Dogrun `gorm:"foreignKey:DogrunID"`
}
