package models

type Success struct {
	Message string      `json:"message"`
	Status  bool        `json:"status"`
	Data    interface{} `json:"data"`
	Token   string      `json:"token"`
}
