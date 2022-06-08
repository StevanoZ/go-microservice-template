package response

import "time"

type ErrorMessageResp struct {
	ID          int64     `json:"id"`
	Topic       string    `json:"topic"`
	OrderingKey string    `json:"orderingKey"`
	ServiceName string    `json:"serviceName"`
	PayloadName string    `json:"payloadName"`
	PayloadData string    `json:"payloadData"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
