package request

type GetErrorMessageReq struct {
	Topic       string `json:"topic" validate:"required"`
	OrderingKey string `json:"orderingKey" validate:"required"`
}
