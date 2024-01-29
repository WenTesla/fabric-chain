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

type LoginRecord struct {
	User     string `form:"user" json:"user" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// 用户注册 上传自己的公钥

func RegisterWithCert(c *gin.Context) {
	id := c.PostForm("id")
	password := c.PostForm("password")
	email := c.PostForm("email")
	// 单文件
	file, err := c.FormFile("publickey")
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
	//先判空
	if id == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg("账号密码为空"),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(id) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	// 用户上传自己的公钥
	err = service.RegisterService(id, password, email, string(bytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.Success())
	return
}

// 用户注册 系统生成，用户的私钥

func RegisterByGenRSA(c *gin.Context) {
	id := c.PostForm("id")
	password := c.PostForm("password")
	email := c.PostForm("email")
	//先判空
	if id == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg("账号密码为空"),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(id) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	var err error = nil
	var bytes []byte = nil
	err, bytes = service.RegisterServiceWithGenRsaKey(id, password, email)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.Writer.WriteHeader(http.StatusOK)
	c.Header("Content-Disposition", fmt.Sprintf("%s.key", id))
	c.Header("Content-Type", "application/text/plain")
	c.Header("Accept-Length", fmt.Sprintf("%d", len(bytes)))
	c.Writer.Write((bytes))
	return

}

// 用户登录 必须附带签名

func Login(c *gin.Context) {
	id := c.PostForm("id")
	password := c.PostForm("password")
	// 单文件
	file, err := c.FormFile("sign")
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
	if id == "" || password == "" {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.UserPasswordIsEmpty),
		)
		return
	}
	// 先校验参数长度
	if len(password) > 32 || len(password) <= 5 || len(id) > 32 {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(config.ParaLengthIsWrong),
		)
		return
	}
	// 登录服务
	err = service.LoginService(id, password, bytes)
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
	userBytes, err := service.UserInfoService(userid)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.JSON(http.StatusOK, model.BaseResponseInstance.SuccessDataBytes(userBytes))
	return
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

func Sign(c *gin.Context) {
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
	id := c.PostForm("id")
	// 用用户的id做签名的原始信息
	sign, err := service.SignService(id, bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest,
			model.BaseResponseInstance.FailMsg(err.Error()),
		)
		return
	}
	// 返回签名值
	c.Writer.WriteHeader(http.StatusOK)
	c.Header("Content-Type", "application/text/plain")
	c.Writer.WriteString(hex.EncodeToString(sign))
	return
}

// 查询用户

func AllUserInfo(c *gin.Context) {
	usersBytes, err := service.AllUserInfoService()
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.Fail())
		return
	}
	c.Writer.WriteHeader(http.StatusOK)
	c.Header("Content-Type", "application/json")
	c.Writer.Write(usersBytes)
	return
}

// 查询用户的历史

func AllUserHistoryInfo(c *gin.Context) {
	id := c.PostForm("id")
	bytes, err := service.UsersHistoryService(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.BaseResponseInstance.FailMsg(err.Error()))
		return
	}
	c.Writer.WriteHeader(http.StatusOK)
	c.Header("Content-Type", "application/json")
	c.Writer.Write(bytes)
	return
}
