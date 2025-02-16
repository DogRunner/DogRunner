package dto

type AuthDogOwnerReq struct {
	Password           string `json:"password"`
	Email              string `json:"email"`
	PhoneNumber        string `json:"phoneNumber"`
	RefreshToken       string `json:"refreshToken"`
	AuthenticationType string `json:"authenticationType"`
}
