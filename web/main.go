package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"web/controller"
)

var port = flag.String("port", "8080", "端口号")

func main() {
	engine := gin.Default()
	//err := engine.Run(":" + *port)
	loadRouter(engine)
	//loadRouter(engine)
	err := engine.Run(":" + *port)
	if err != nil {
		panic(err)
	}
}

func loadRouter(r *gin.Engine) {
	// 注册接口 todo
	r.POST("/user/registerWithKey", controller.RegisterWithCert)
	// 注册接口
	r.POST("/user/registerByGenKey", controller.RegisterByGenRSA)
	//r.GET("/user/register/", controller.Register)
	// 登录接口
	r.POST("/user/login/", controller.Login)
	// 查询接口
	r.POST("/user/info", controller.UserInfo)
	// 修改密码
	r.POST("/user/updatePassword", controller.UpdatePassword)
	// 注册证书
	r.POST("/cert/register", controller.CertRegister)
	// 验证证书数据
	r.POST("/chain/verity", controller.VerityCertController)
}
