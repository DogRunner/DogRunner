package core

// token authentication
const (
	CONTEXT_KEY   string = "user_info"
	TOKEN_LOOK_UP string = "header:Authorization:Bearer " // `Bearer `しか切り取れないのでスペースが多い場合は未対応
)

// role
const (
	SYSTEM              int = 0
	DOGRUNMG_ROLE       int = 1
	DOGRUNMG_ADMIN_ROLE int = 2
	DOGOWNER_ROLE       int = 3
	GENERAL             int = 100
)

// 一般ユーザーのUserID
const (
	GENERAL_USER_ID     int64  = -999
	GENERAL_USER_JWT_ID string = "general"
)
