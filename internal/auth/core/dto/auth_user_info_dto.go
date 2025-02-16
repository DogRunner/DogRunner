package dto

type AuthUserInfoDTO struct {
	UserID int64
	RoleID int
}

type JwtInfoDTO struct {
	AuthUserInfoDTO
	JwtID        string
	RefreshJwtID string
}

type IssuedJwtRes struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
}
