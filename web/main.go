package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"web/controller"
)

// 默认端口号 8080
var port = flag.String("port", "8080", "端口号")

func main() {
	engine := gin.Default()
	loadRouter(engine)
	err := engine.Run(":" + *port)
	if err != nil {
		panic(err)
	}
}

func loadRouter(r *gin.Engine) {
	// 注册接口
	r.POST("/user/registerWithKey", controller.RegisterWithCert)
	// 注册接口
	r.POST("/user/registerByGenKey", controller.RegisterByGenRSA)
	// 登录接口
	r.POST("/user/login/", controller.Login)
	// 查询接口
	r.POST("/user/info", controller.UserInfo)
	// 查询所有用户接口
	r.POST("/user/allUser", controller.AllUserInfo)
	// 查询用户的交易历史
	r.POST("/user/userHistory", controller.AllUserHistoryInfo)
	// 修改密码
	r.POST("/user/updatePassword", controller.UpdatePassword)
	// 注册证书
	r.POST("/cert/register", controller.RegisterCert)
	// 验证证书数据
	r.POST("/chain/verity", controller.VerityCert)
	// 所有证书
	r.POST("/chain/all", controller.AllCert)
	// 签名
	r.POST("/user/sign", controller.Sign)

}
