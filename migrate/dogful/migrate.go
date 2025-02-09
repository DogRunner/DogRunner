package main

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

/*
dog-fulからのマイグレート
*/
type DogFulJson struct {
	ID               int         `json:"id"`
	Name             string      `json:"name"`
	PrefectureID     int         `json:"prefecture_id"`
	Address1         string      `json:"address1"`
	Address2         string      `json:"address2"`
	Tel              string      `json:"tel"`
	Url              string      `json:"url"`
	BusinessHourDesc string      `json:"open_hour_free_text"`
	Catch            string      `json:"catch"`
	Content          string      `json:"content"`
	Lonlat           Lonlat      `json:"lonlat"`
	DogrunTags       []DogrunTag `json:"dog_run_feature_tags"`
}

type Lonlat struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type DogrunTag struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	NameEn string `json:"slug"`
}

var prefectures = map[int]string{
	1:  "北海道",
	2:  "青森県",
	3:  "岩手県",
	4:  "宮城県",
	5:  "秋田県",
	6:  "山形県",
	7:  "福島県",
	8:  "茨城県",
	9:  "栃木県",
	10: "群馬県",
	11: "埼玉県",
	12: "千葉県",
	13: "東京都",
	14: "神奈川県",
	15: "新潟県",
	16: "富山県",
	17: "石川県",
	18: "福井県",
	19: "山梨県",
	20: "長野県",
	21: "岐阜県",
	22: "静岡県",
	23: "愛知県",
	24: "三重県",
	25: "滋賀県",
	26: "京都府",
	27: "大阪府",
	28: "兵庫県",
	29: "奈良県",
	30: "和歌山県",
	31: "鳥取県",
	32: "島根県",
	33: "岡山県",
	34: "広島県",
	35: "山口県",
	36: "徳島県",
	37: "香川県",
	38: "愛媛県",
	39: "高知県",
	40: "福岡県",
	41: "佐賀県",
	42: "長崎県",
	43: "熊本県",
	44: "大分県",
	45: "宮崎県",
	46: "鹿児島県",
	47: "沖縄県",
}

// [dogfulTagId] : wanrunTagId
var tagMapping = map[int]int{
	12: 20,
	21: 7,
	22: 21,
	23: 15,
	24: 18,
	25: 26,
	26: 17,
	27: 2,
	28: 13,
	29: 12,
	30: 24,
	31: 19,
	32: 25,
	37: 10,
	46: 14,
}

func main() {
	// JSON gzipファイルを開く
	srcGzFile, err := os.Open("./dogruns.json.gz")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer srcGzFile.Close()

	// gzipリーダーを作成
	gzReader, err := gzip.NewReader(srcGzFile)
	if err != nil {
		fmt.Printf("Failed to create gzip reader: %v\n", err)
		return
	}
	defer gzReader.Close()

	// JSONを構造体にデコード
	var dogruns []DogFulJson
	if err := json.NewDecoder(gzReader).Decode(&dogruns); err != nil {
		fmt.Println("Error:", err)
		return
	}

	exec(dogruns)
}

var dogrunsInsertSql = `INSERT INTO dogruns (place_id, dogrun_manager_id, name, address, tel, url, latitude, longitude, business_hour_desc, description, is_managed, reg_at, upd_at) VALUES
	(null, null, $1, $2, $3, $4, $5, $6, $7, $8, false, NOW(), NOW()) RETURNING dogrun_id;`
var dogrunTagsInsertSql = "INSERT INTO dogrun_tags (dogrun_id, tag_id) VALUES ($1, $2);"

func exec(dogruns []DogFulJson) {
	// PostgreSQL接続文字列
	postgresUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		"localhost", // hostOSから実行する想定のため明示的に指定
		"5555",      // host portを明示的に指定
		os.Getenv("POSTGRES_DB"))

	// データベース接続
	db, err := sql.Open("postgres", postgresUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("Failed to begin transaction: %v", err)
	}

	for _, dogrun := range dogruns {
		var dogrunID int
		err := tx.QueryRow(dogrunsInsertSql,
			dogrun.Name,
			prefectures[dogrun.PrefectureID]+dogrun.Address1+dogrun.Address2,
			dogrun.Tel,
			dogrun.Url,
			dogrun.Lonlat.X,
			dogrun.Lonlat.Y,
			dogrun.BusinessHourDesc,
			dogrun.Catch+"\n"+dogrun.Content,
		).Scan(&dogrunID)
		if err != nil {
			errExit(tx, err)
		}

		fmt.Printf("insert is success. dogrun id :%d\n", dogrunID)

		if err != nil {
			errExit(tx, err)
		}

		for _, tag := range dogrun.DogrunTags {
			if tagMapping[tag.ID] == 0 {
				continue
			}
			_, err = tx.Exec(dogrunTagsInsertSql,
				dogrunID,
				tagMapping[tag.ID],
			)
			if err != nil {
				fmt.Printf("dogful_dogrun_id:%d, dogful_tag_id:%d, wanrun_tag_id:%d\n", dogrun.ID, tag.ID, tagMapping[tag.ID])
				errExit(tx, err)
			}
		}

	}

	fmt.Printf("コミットします\n")
	if err := tx.Commit(); err != nil {
		log.Fatalf("Failed to commit transaction: %v\n", err)
	}

	fmt.Printf("Inserted new record. total count :%d\n", len(dogruns))
}

func errExit(tx *sql.Tx, err error) {
	fmt.Printf("エラーのためロールバック\n")
	_ = tx.Rollback() // エラー時にロールバック
	log.Fatalf("Failed to insert data: %v\n", err)
}
