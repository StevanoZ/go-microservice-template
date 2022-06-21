package request

type PaginationReq struct {
	Page        int    `json:"page"`
	Limit       int    `json:"limit"`
	SearchField string `json:"searchField"`
	SearchValue string `json:"searchValue"`
	FilterBy    string `json:"filterBy"`
	SortBy      string `json:"sortBy"`
	IsCache     string `json:"IsCache"`
}
