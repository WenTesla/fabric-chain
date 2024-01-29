package controller

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"strings"
	"web/config"
	"web/model"
	"web/service"
)

// 申请证书
// 下载到本地

func RegisterCert(c *gin.Context) {
	csr, err := c.FormFile("csr")
	pub, err := c.FormFile("pub")
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	csrFile, err := csr.Open()
	pubFile, err := pub.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	csrBytes, _ := io.ReadAll(csrFile)
	pubBytes, _ := io.ReadAll(pubFile)
	bytes, err := service.CertRegisterService(string(csrBytes), string(pubBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	log.Printf("%s", bytes)
	//c.IndentedJSON(http.StatusOK, model.BaseResponseInstance.SuccessData(string(bytes)))
	//c.Header("Content-Disposition", fmt.Sprintf("%s.key",))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write(bytes)
	return
}

//

func VerityCert(c *gin.Context) {
	cert, err := c.FormFile("cert")
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	certFile, err := cert.Open()
	defer certFile.Close()
	certBytes, err := io.ReadAll(certFile)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	// 验证证书
	IsTrue, err := service.VerityCertService(string(certBytes))
	if err != nil || !IsTrue {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(err.Error()),
		)
		return
	}
	c.JSON(http.StatusOK,
		model.BaseResponseInstance.Success(),
	)
	return
}

func AllCert(c *gin.Context) {
	bytes, err := service.CertAllService()
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	fmt.Println(strings.ReplaceAll(string(bytes), "\\n", ""))
	//c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(fmt.Sprintf("%s", bytes)))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write(bytes)

	return
}
