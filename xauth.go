package xauth

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

type Request struct {
	data XParamSlice
}

type XParam struct {
	Key   string
	Value interface{}
}

type XParamSlice []*XParam

func (x XParamSlice) Len() int {
	return len(x)
}

func (x XParamSlice) Less(i, j int) bool {
	return x[i].Key < x[j].Key
}

func (x XParamSlice) Swap(i, j int) {
	tmp := x[i]
	x[i] = x[j]
	x[j] = tmp
}

type XAuth struct {
	AppKey    string `json:"appKey"`
	Sign      string `json:"sign"`
	Timestamp int64  `json:"timestamp"`

	AppSecret string      `json:"appSecret"`
	Params    XParamSlice `json:"params"`

	KeyValues string `json:"-"`
	MD5Value  string `json:"-"`
}

// 计算签名
func (a *XAuth) GetSign() {
	// 将参数key按照ASCII顺序排列
	sort.Sort(a.Params)

	// 连接key和它对应的value
	a.GetKeyValues()

	a.GetMD5()

	a.Sign = strings.ToUpper(a.MD5Value)
}

// 获取参数keyvalue值
func (a *XAuth) GetKeyValues() {
	keyValues := ""
	for _, p := range a.Params {
		keyValues += fmt.Sprintf("%s%v", p.Key, p.Value)
	}

	a.KeyValues = keyValues
}

// 计算MD5
func (a *XAuth) GetMD5() {
	hash := md5.New()
	hash.Write([]byte(fmt.Sprintf("%s%s", a.AppSecret, a.KeyValues)))
	src := hash.Sum(nil)
	a.MD5Value = hex.EncodeToString(src)
}

// 判断timestamp是否过期，误差+-7分钟
func (a *XAuth) IsExpired() bool {
	currentTime := time.Now()
	paramTime := time.Unix(a.Timestamp/1000, 0)

	maxTime := paramTime.Add(time.Minute * 7)
	minTime := paramTime.Add(-1 * time.Minute * 7)

	log.Println(maxTime, minTime, currentTime)

	if currentTime.Before(maxTime) && currentTime.After(minTime) {
		return false
	}

	return true
}

// 是否验证通过
func (a *XAuth) IsAuthPass(targetSign string) bool {
	a.GetSign()
	return strings.EqualFold(a.Sign, targetSign)
}
