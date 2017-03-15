package xauth

import (
	"encoding/json"
	"log"
	"sort"
	"testing"
)

var appData map[string]string

func Init() {
	appData = make(map[string]string)
	// 存放appKey和对应的secret
	appData["appKey"] = "appSecret"
}

// TODO:body体支持复杂参数
// 测试使用postbody体参数进行加密
func TestPostBodyParams(t *testing.T) {
	Init()
	// appKey, targetSign, timestamp从get参数获取
	// 用户计算sign的数据从 body json 获取
	appKey := "appKey"
	targetSign := "BF74FE92B54480C3A296C3349DF71AA3"
	var timestamp int64 = 1489485646000

	jsonData := "{\"appKey\":\"appKey\",\"timestamp\":1489485646000}"

	req := new(Request)
	json.Unmarshal([]byte(jsonData), req)

	// 1.param赋值，appSecret获取，timestamp赋值
	a := new(XAuth)
	a.AppSecret = appData[appKey]

	if a.AppSecret == "" || len(a.AppSecret) == 0 {
		log.Println("无效appKey")
		return
	}

	a.Timestamp = timestamp

	a.Params = req.Data

	// 2.判断是否过期
	if a.IsExpired() {
		log.Println("失效")
		return
	}

	// 3.判断sign参数是否和计算的sign相同
	if !a.IsAuthPass(targetSign) {
		log.Println("签名错误", a.Sign)
		return
	}

	log.Println("通过验证")
}

// 测试使用url连接参数进行加密
func TestGetParams(t *testing.T) {
    Init()
    // appKey, targetSign, timestamp从get参数获取
    // 用户计算sign的数据从 body json 获取
    appKey := "appKey"
    targetSign := "DB07596AA304F3BA6BBB74B42D9685F6"
    var timestamp int64 = 1489546332000

    req := new(Request)

    ak := new(XParam)
    ak.Key = "appKey"
    ak.Value = "appKey"
    ts := new(XParam)
    ts.Key = "timestamp"
    ts.Value = 1489546332000

    req.Data = append(req.Data, ak)
    req.Data = append(req.Data, ts)

    // 1.param赋值，appSecret获取，timestamp赋值
    a := new(XAuth)
    a.AppSecret = appData[appKey]

    if a.AppSecret == "" || len(a.AppSecret) == 0 {
        log.Println("无效appKey")
        return
    }

    a.Timestamp = timestamp

    a.Params = req.Data

    // 2.判断是否过期
    if a.IsExpired() {
        log.Println("失效")
        return
    }

    // 3.判断sign参数是否和计算的sign相同
    if !a.IsAuthPass(targetSign) {
        log.Println("签名错误", a.Sign)
        return
    }

    log.Println("通过验证")
}

// 测试key排序
func TestKeySort(t *testing.T) {
	a := new(XAuth)
	p1 := new(XParam)
	p1.Key = "apple"
	p1.Value = "apple"

	p2 := new(XParam)
	p2.Key = "banana"
	p2.Value = "banana"

	p3 := new(XParam)
	p3.Key = "pear"
	p3.Value = "pear"

	p4 := new(XParam)
	p4.Key = "orange"
	p4.Value = "orange"

	p5 := new(XParam)
	p5.Key = "mango"
	p5.Value = "mango"

	p6 := new(XParam)
	p6.Key = "cherry"
	p6.Value = "cherry"

	a.Params = append(a.Params, p1)
	a.Params = append(a.Params, p2)
	a.Params = append(a.Params, p3)
	a.Params = append(a.Params, p4)
	a.Params = append(a.Params, p5)
	a.Params = append(a.Params, p6)

	log.Println("排序前：")
	for _, v := range a.Params {
		log.Println(v)
	}

	// 测试的方法
	sort.Sort(a.Params)

	log.Println("排序后：")
	for _, v := range a.Params {
		log.Println(v)
	}
}

// 测试key value连接
func TestXAuth_GetKeyValues(t *testing.T) {
	a := new(XAuth)
	p1 := new(XParam)
	p1.Key = "key1"
	p1.Value = "value1"

	p2 := new(XParam)
	p2.Key = "key2"
	p2.Value = "value2"

	a.Params = append(a.Params, p1)
	a.Params = append(a.Params, p2)

	// 测试的方法
	a.GetKeyValues()

	log.Println(a.KeyValues)
}

// 测试MD5加密
func TestXAuth_GetMD5(t *testing.T) {
	a := new(XAuth)

	a.KeyValues = "xxdw"

	// 测试的方法
	a.GetMD5()

	log.Println(a.MD5Value)
}

// 测试签名
func TestXAuth_GetSign(t *testing.T) {
	a := new(XAuth)
	p1 := new(XParam)
	p1.Key = "key1"
	p1.Value = "value1"

	p2 := new(XParam)
	p2.Key = "key2"
	p2.Value = "value2"

	a.Params = append(a.Params, p1)
	a.Params = append(a.Params, p2)

	// 测试的方法
	a.GetSign()

	log.Println(a.Sign)
}

// 测试timestamp是否失效
func TestXAuth_IsExpired(t *testing.T) {
	a := new(XAuth)
	a.Timestamp = 1489384949000

	log.Println(a.IsExpired())
}

// 测试sign是否一致
func TestXAuth_IsAuthPass(t *testing.T) {
	a := new(XAuth)
	p1 := new(XParam)
	p1.Key = "key1"
	p1.Value = "value1"

	p2 := new(XParam)
	p2.Key = "key2"
	p2.Value = "value2"

	a.Params = append(a.Params, p1)
	a.Params = append(a.Params, p2)

	// 测试的方法
	log.Println(a.IsAuthPass("90D6F6B9AFC9C4173D43BA1918D84702"))
}
