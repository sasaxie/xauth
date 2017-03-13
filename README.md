# xauth
Golang auth

## 介绍
主要用于API接口认证。

## Installation
> go get github.com/Vickixiaodong/xauth

## 使用说明
前端应用请求接口POST方式：
```
post:http://api.test.com/v1/xxx?appKey=appKey&sign=sign&timestamp=1489387377000
```
用于验证的参数放在请求body里：
```json
{
  "appKey":"appKey",
  "timestamp":1489387377000,
  "param1":"value1"
}
```
> timestamp单位为毫秒，body必须包含appKey和timestamp

## 签名计算方式
用于验证的参数key按照ASCII顺序排列，跟上对应的值(key1value1key2value2...)，然后将appSecret放在头部(appSecretkey1value1key2value2...)，进行MD5加密，全部大写。
