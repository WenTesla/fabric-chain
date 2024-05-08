package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	"net/http"
	"web/controller"
	"web/model"
)

// 默认端口号 8080
var port = flag.String("port", "8080", "端口号")

func main() {
	engine := gin.Default()
	engine.Use(Cors())
	loadRouter(engine)
	err := engine.Run(":" + *port)
	if err != nil {
		panic(err)
	}
}
func Cors() gin.HandlerFunc {
	return func(context *gin.Context) {
		method := context.Request.Method
		context.Header("Access-Control-Allow-Origin", "*")
		context.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token")
		context.Header("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
		context.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		context.Header("Access-Control-Allow-Credentials", "true")
		if method == "OPTIONS" {
			context.AbortWithStatus(http.StatusNoContent)
		}
		context.Next()
	}
}

func loadRouter(r *gin.Engine) {
	// 注册（携带密钥)
	r.POST("/api/user/registerWithKey", controller.RegisterWithCert)
	// 注册接口(自己生成密钥)
	r.POST("/api/user/registerByGenKey", controller.RegisterByGenRSA)
	// 登录接口
	r.POST("/api/user/login", controller.Login)
	// 查询接口
	r.POST("/api/user/info", controller.UserInfo)
	// 查询所有用户接口
	r.POST("/api/user/allUser", controller.AllUserInfo)
	// 查询用户的历史
	r.POST("/api/user/userHistory", controller.AllUserHistoryInfo)
	// 修改密码
	r.POST("/api/user/updatePassword", controller.UpdatePassword)
	// 升级
	r.POST("/api/user/upgrade", controller.Upgrade)
	// 降级
	r.POST("/api/user/degrade", controller.Degrade)
	// 禁用用户
	r.POST("/api/user/ban", controller.BanUser)
	// 解禁用户
	r.POST("/api/user/unban", controller.UnBanUser)
	// 签名
	r.POST("/api/user/sign", controller.Sign)
	// 删除用户
	r.POST("/api/user/delete", controller.DeleteUser)
	// 获取用户角色
	r.POST("/api/user/role", controller.UserRole)
	// 生成csr
	r.POST("/api/cert/csr", controller.RegisterCsr)
	// 注册中间证书
	r.POST("/api/cert/registerIntermediateCert", controller.RegisterIntermediateCert)
	// 撤销中间证书
	r.POST("/api/cert/deleteIntermediateCert", controller.RevokeIntermediateCert)
	// 验证证书数据
	r.POST("/api/chain/verity", controller.VerityCert)
	// 所有中间证书信息
	r.POST("/api/chain/all", controller.AllIntermediateCert)
	// 证书查询接口
	r.POST("/api/cert/info", controller.CertInfo)
	// 注册终端证书
	r.POST("/api/cert/registerCert", controller.RegisterCert)
	// 批准终端证书
	r.POST("/api/cert/approve", controller.ApproveCert)
	// 撤销终端证书
	r.POST("/api/cert/revoke", controller.RevokeCert)
	//删除终端证书
	r.POST("/api/cert/delete", controller.DeleteCert)
	// 所有终端证书信息
	r.POST("/api/cert/allCert", controller.AllCert)
	// 用户申请的终端证书
	r.POST("/api/cert/myCert", controller.MyCert)
	// 下载证书

	//其他
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, model.BaseResponseInstance.FailMsg("页面不存在"))
	})
}
