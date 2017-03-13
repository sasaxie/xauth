package xauth

import (
    "testing"
    "log"
    "sort"
    "encoding/json"
)

// 测试整个流程
func TestAll(t *testing.T) {
    // appKey, targetSign, timestamp从get参数获取
    // 用户计算sign的数据从 body json 获取
    appKey := "appKey"
    targetSign := "368480924A6C78E2E8681551A7CF4C21"
    var timestamp int64 = 1489387377000

    jsonData := "{\"appKey\":\"appKey\",\"timestamp\":1489387377000}"

    req := new(Request)
    json.Unmarshal([]byte(jsonData), req)

    // 1.param赋值，appSecret获取，timestamp赋值
    a := new(XAuth)
    a.AppSecret = appKey
    a.Timestamp = timestamp

    a.Params = req.data

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