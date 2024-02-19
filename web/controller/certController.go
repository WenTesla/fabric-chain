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

// 创建证书请求

func RegisterCsr(c *gin.Context) {
	c.PostForm("CN")
	c.PostForm("")

}

// 申请中间证书

func RegisterIntermediateCert(c *gin.Context) {
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
	bytes, err := service.IntermediateCertRegisterService(string(csrBytes), string(pubBytes))
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

// 注册证书

func RegisterCert(c *gin.Context) {
	csr, err := c.FormFile("csr")
	csrFile, err := csr.Open()
	csrBytes, err := io.ReadAll(csrFile)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	log.Printf("%s", csrBytes)
	Id := c.PostForm("userId")
	err = service.RegisterCertService(Id, csrBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 批准中间证书

func ApproveCert(c *gin.Context) {
	id := c.PostForm("id")
	_, err := service.ApproveCertService(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 撤销中间证书

func RevokeIntermediateCert(c *gin.Context) {
	id := c.PostForm("id")
	_, err := service.RevokeIntermediateService(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

//查询中间证书

func AllCert(c *gin.Context) {
	bytes, err := service.AllCertService()
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.Writer.WriteString(strings.ReplaceAll(string(bytes), "\\n", ""))
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

func AllIntermediateCert(c *gin.Context) {
	bytes, err := service.CertAllService()
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	fmt.Println(strings.ReplaceAll(string(bytes), "\\n", ""))
	//c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(fmt.Sprintf("%s", bytes)))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	//c.Writer.Write(bytes)
	c.Writer.WriteString(strings.ReplaceAll(string(bytes), "\\n", ""))
	return
}

// 查询证书信息(pem格式)(不调用链码)

func CertInfo(c *gin.Context) {
	// 获取证书
	file, err := c.FormFile("cert")
	certFile, err := file.Open()
	bytes, err := io.ReadAll(certFile)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	certificate, err := service.ParseCertService(bytes)
	if err != nil {
		// 返回错误信息
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(certificate))
	return
}
