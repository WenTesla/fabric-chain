package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"strconv"
	"web/config"
	"web/model"
	"web/service"
)

// 创建证书请求csr

func RegisterCsr(c *gin.Context) {
	form := struct {
		C            string `form:"C" binding:"required"`
		ST           string `form:"ST"`
		L            string `form:"l"`
		O            string `form:"o"`
		OU           string `form:"OU"`
		CN           string `form:"CN"`
		EmailAddress string `form:"emailAddress"`
		DnsEmail     string `form:"Dns"`
	}{}
	if c.ShouldBind(&form) != nil {
		c.JSON(http.StatusUnauthorized,
			model.BaseResponseInstance.FailMsg(config.RequestParameterIsNull),
		)
		return
	}
	log.Printf("%v", form)
	// 获取私钥
	pri, err := c.FormFile("pri")
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	file, err := pri.Open()
	priBytes, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusUnauthorized,
			model.BaseResponseInstance.FailMsg(err.Error()),
		)
		return
	}
	bytes, err := service.RegisterCsrService(pkix.Name{
		Country:            []string{form.CN},
		Organization:       []string{form.O},
		OrganizationalUnit: []string{form.OU},
		Locality:           []string{form.L},
		Province:           []string{},
		StreetAddress:      []string{form.ST},
		PostalCode:         []string{""},
		SerialNumber:       "",
		CommonName:         form.C,
		Names:              nil,
		ExtraNames:         nil,
	}, []string{form.DnsEmail}, []string{form.EmailAddress}, priBytes)
	if err != nil {
		c.JSON(http.StatusUnauthorized,
			model.BaseResponseInstance.FailMsg(err.Error()),
		)
		return
	}
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write(bytes)
	return
}

// 申请中间证书

func RegisterIntermediateCert(c *gin.Context) {
	csr, err := c.FormFile("csr")
	//pub, err := c.FormFile("pub")
	if err != nil {
		c.JSON(http.StatusOK,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	csrFile, err := csr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	csrBytes, _ := io.ReadAll(csrFile)
	//pubBytes, _ := io.ReadAll(pubFile)
	bytes, err := service.IntermediateCertRegisterService(string(csrBytes), c.PostForm("id"))
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

// 注册上传证书

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
	bytes, err := service.RegisterCertService(Id, csrBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(string(bytes)))
	return
}

// 批准证书

func ApproveCert(c *gin.Context) {
	id := c.PostForm("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(config.RequestFail))
		return
	}
	// 获取中间证书的私钥
	pri, err := c.FormFile("pri")
	csrFile, err := pri.Open()
	priBytes, err := io.ReadAll(csrFile)
	if c.PostForm("userId") == "" || c.PostForm("issuerId") == "" || c.PostForm("interId") == "" {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(config.RequestParameterIsNull))
		return
	}
	bytes, err := service.ApproveCertService(id, c.PostForm("userId"), c.PostForm("issuerId"), c.PostForm("interId"), string(priBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(string(bytes)))
	return
}

// 撤销终端证书

func RevokeCert(c *gin.Context) {
	id := c.PostForm("id")
	if _, err := service.RevokeCertService(id); err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 撤销中间证书

func RevokeIntermediateCert(c *gin.Context) {
	id := c.PostForm("id")
	if _, err := service.RevokeIntermediateService(id); err != nil {
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
	//c.Writer.WriteString(strings.ReplaceAll(string(bytes), "\\n", ""))
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

func AllIntermediateCert(c *gin.Context) {
	bytes, err := service.CertAllService()
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	//fmt.Println(strings.ReplaceAll(string(bytes), "\\n", ""))
	//c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(fmt.Sprintf("%s", bytes)))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write(bytes)
	//c.Writer.WriteString(strings.ReplaceAll(string(bytes), "\\n", ""))
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

// 删除证书

func DeleteCert(c *gin.Context) {
	id := c.PostForm("id")
	if _, err := service.DeleteCertService(id); err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 用户自己的证书

func MyCert(c *gin.Context) {
	id := c.PostForm("id")
	if bytes, err := service.MyCertService(id); err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	} else {
		c.Writer.Write(bytes)
	}
	return

}

//

func GenRSA(c *gin.Context) {
	bit, _ := strconv.Atoi(c.PostForm("bit"))
	key, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	// pem编码
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(key)
	memoryPrivateKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalPKCS1PrivateKey,
	})
	c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessData(memoryPrivateKey))
}
