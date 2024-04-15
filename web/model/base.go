package model

const (
	success = "success"
	fail    = "fail"
)

type BaseResponse struct {
	// 状态码
	StatusCode int8 `json:"status_code"`
	// 状态响应信息
	StatusMsg string `json:"status_msg,omitempty"`
	// 数据
	Data any `json:"data,omitempty"`
}

var BaseResponseInstance = BaseResponse{}

func (*BaseResponse) Success() (response BaseResponse) {
	response.StatusCode = 0
	response.StatusMsg = success
	return
}

func (*BaseResponse) Fail() (response BaseResponse) {
	response.StatusCode = -1
	response.StatusMsg = fail
	return
}

func (*BaseResponse) SuccessMsg(msg string) (response BaseResponse) {
	response.StatusCode = 0
	response.StatusMsg = msg
	return
}
func (*BaseResponse) FailMsg(msg string) (response BaseResponse) {
	response.StatusCode = -1
	response.StatusMsg = msg
	return
}

func (*BaseResponse) SuccessData(data any) (response BaseResponse) {
	response.StatusCode = 0
	response.Data = data
	return
}
func (*BaseResponse) FailData(data string) (response BaseResponse) {
	response.StatusCode = -1
	response.StatusMsg = data
	return
}
func (*BaseResponse) SuccessDataBytes(data []byte) (response BaseResponse) {
	response.StatusCode = 0
	response.Data = data
	return
}
