package model

import "web/config"

type BaseResponse struct {
	// 状态码
	StatusCode int8 `json:"status_code"`
	// 状态响应信息
	StatusMsg string `json:"status_msg,omitempty"`
	// 数据
	Data any `json:"data,omitempty"`
}

var BaseResponseInstance = BaseResponse{}

func (baseResponse *BaseResponse) Success() BaseResponse {
	baseResponse.StatusCode = 0
	baseResponse.StatusMsg = config.Success
	return BaseResponseInstance
}

func (baseResponse *BaseResponse) Fail() BaseResponse {
	baseResponse.StatusCode = -1
	baseResponse.StatusMsg = config.Fail
	return BaseResponseInstance
}

func (baseResponse *BaseResponse) SuccessMsg(msg string) BaseResponse {
	baseResponse.StatusCode = 0
	baseResponse.StatusMsg = msg
	return BaseResponseInstance
}
func (baseResponse *BaseResponse) FailMsg(msg string) BaseResponse {
	baseResponse.StatusCode = -1
	baseResponse.StatusMsg = msg
	return BaseResponseInstance
}

func (baseResponse *BaseResponse) SuccessData(data string) BaseResponse {
	baseResponse.StatusCode = 0
	baseResponse.Data = data
	return BaseResponseInstance
}
func (baseResponse *BaseResponse) FailData(data string) BaseResponse {
	baseResponse.StatusCode = -1
	baseResponse.StatusMsg = data
	return BaseResponseInstance
}
func (baseResponse *BaseResponse) SuccessDataBytes(data []byte) BaseResponse {
	baseResponse.StatusCode = 0
	baseResponse.Data = data
	return BaseResponseInstance
}

func (baseResponse *BaseResponse) Response(httpCode int8, Msg string, data any) BaseResponse {
	baseResponse.StatusCode = httpCode
	baseResponse.StatusMsg = Msg
	baseResponse.Data = data
	return BaseResponseInstance
}
