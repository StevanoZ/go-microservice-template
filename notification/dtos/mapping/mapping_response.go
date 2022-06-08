package mapping

import (
	querier "github.com/StevanoZ/dv-notification/db/repository"
	"github.com/StevanoZ/dv-notification/dtos/response"
)

func ToErrorMessageResp(errMsg querier.ErrorMessage) response.ErrorMessageResp {
	return response.ErrorMessageResp{
		ID:          errMsg.ID,
		ServiceName: errMsg.ServiceName,
		OrderingKey: errMsg.OrderingKey,
		Topic:       errMsg.Topic,
		PayloadName: errMsg.PayloadName,
		PayloadData: errMsg.PayloadData,
		Description: errMsg.Description,
		CreatedAt:   errMsg.CreatedAt,
		UpdatedAt:   errMsg.UpdatedAt,
	}
}
