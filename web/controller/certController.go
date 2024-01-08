package controller

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"web/model"
)

// 申请证书
// 下载到本地

func CertRegister(c *gin.Context) {

	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
}

func VerityCert(c *gin.Context) {
}
