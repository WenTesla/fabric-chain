package controller

import (
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"web/config"
	"web/model"
	"web/service"
)

// 用户注册 上传自己的公钥

func RegisterWithCert(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	email := c.PostForm("email")
	PublicKey := c.PostForm("PublicKey")

	// 单文件
	file, _ := c.FormFile("file")
	log.Println(file.Filename)

	//先判空
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg("账号密码为空"),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(username) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	var err error = nil
	// 用户生成密钥对
	err = service.RegisterService(username, password, email, PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 用户注册 系统生成，用户的私钥

func RegisterByGenRSA(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	email := c.PostForm("email")
	//先判空
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg("账号密码为空"),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(username) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	var err error = nil
	var bytes []byte = nil
	err, bytes = service.RegisterServiceWithGenRsaKey(username, password, email)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.Writer.WriteHeader(http.StatusOK)
	c.Header("Content-Disposition", fmt.Sprintf("%s.key", username))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write((bytes))
	return

}

// 用户登录 必须附带pki颁发的私钥

func Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	// 单文件
	file, err := c.FormFile("privateKey")
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	log.Println(file.Filename)
	// 取出数据
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	defer src.Close()
	bytes, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}

	//先判空
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg("账号密码为空"),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(username) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	// 密钥
	err = service.LoginService(username, password, bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 查询用户的信息

func UserInfo(c *gin.Context) {
	userid := c.PostForm("id")
	user, err := service.UserInfoService(userid)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"UserInfo": user,
	})
}

// 修改密码

func UpdatePassword(c *gin.Context) {
	// 用户Id
	userId := c.PostForm("userId")
	// 密码
	password := c.PostForm("password")
	err := service.UpdateService(userId, password)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 签名
func SignController(c *gin.Context) {
	// 单文件
	file, err := c.FormFile("privateKey")
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileUploadFalse),
		)
		return
	}
	log.Println(file.Filename)
	// 取出数据
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	defer src.Close()
	bytes, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.FileParseFalse),
		)
		return
	}
	//data := c.PostForm("data")
	sign, err := service.SignService(service.SignValue, bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(err.Error()),
		)
		return
	}
	// 返回签名值
	c.JSON(http.StatusOK,
		model.BaseResponseInstance.SuccessMsg(hex.EncodeToString(sign)),
	)
	return
}

func VerityController(c *gin.Context) {
	data := c.PostForm("data")
	id := c.PostForm("id")
	if data == "" || id == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.RequestParameterIsNull),
		)
		return
	}
	Flag := service.VerifySignService(id, []byte(data))
	if !Flag {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.SignIsWrong),
		)
		return
	}
	c.JSON(http.StatusOK,
		model.BaseResponseInstance.Success(),
	)
	return
}
