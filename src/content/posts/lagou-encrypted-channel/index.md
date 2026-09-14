---
title: 拉勾 加密信道逆向——RSA 密钥协商 + AES256CBC 请求加密 + SHA256 签名，纯 Python 复现（密钥协商实测打通）
summary: 逆整条加密信道：RSA 密钥协商 → AES256CBC 请求加密 → SHA256 签名信封；纯 Python 复现，密钥协商实测打通。
created: '2026-09-03'
tags:
  - 移动安全
  - 逆向
  - 协议
  - 加密信道
  - 密钥协商
  - RSA
  - AES
  - 签名
  - 纯算复现
target: com.alpha.lagouapk（拉勾招聘）v8.30.0
source: 发表文章/某招聘App-加密信道协议逆向/招聘App_加密信道协议逆向_看雪版.md
---

这个招聘 App 百度加固，先内存脱壳（另一篇讲过，root 读 `/proc/pid/mem` 绕页权限，出 19973 类、方法体完整）。脱出来看它的网络层 `com.lagou.socketchannel.http`，不是普通加 header，是一整套加密信道：先跟服务器协商一个会话 AES key，之后每个请求体 AES 加密、带签名。本文把这套协议逆出来，纯 Python 复现，最后拿真实服务器验证密钥协商。

样本 v8.30.0（`com.alpha.lagouapk`），网关 `gate.lagou.com`。

## 密钥协商：客户端造 key，RSA 加密给服务器

入口 `SecretHttpController`。协商流程在 `b(boolean, callback)`：

```java
final String strBfK = AES256CBC.bfK();              // 客户端随机 AES key K_c
String strEL = RSAEncoder.EL(strBfK);               // RSA 公钥加密 K_c
SecretAgreementReq req = new SecretAgreementReq();
req.setSecretKeyDecode(strEL);
// POST -> 回调里:
String sessionKey = AES256CBC.decode(strBfK, resp.getSecretKeyValue());   // K_s = AES.decode(K_c, 服务器返回值)
this.gOc = strBfK; this.kkg = resp;                 // 存下来
```

拆开每一块：

- `AES256CBC.bfK()` = `toHexString(KeyGenerator AES 128)`，生成 16 字节随机 key，转成 32 个 hex 字符。这 32 字符串**当作 AES key 用**（32 字节 = AES-256）。
- `RSAEncoder.EL(s)` = `base64(RSA/ECB/PKCS1Padding(pubkey, utf8(s)))`。公钥哪来的？`RSAEncoder.getPublicKey()` 从 `assets/lagou.crt` 读 X.509 证书取公钥，2048 位，**在 APK 里，直接抽出来**。
- 服务器收到 `RSA(K_c)`，回一个 `secretKeyValue`。客户端 `K_s = AES256CBC.decode(K_c, secretKeyValue)`：**服务器把真正的会话 key 用 K_c 加密回来，客户端解出来**。

AES256CBC 的参数也是死的：

```java
private static final String hoL = "AES/CBC/PKCS5Padding";
private static final byte[] hoK = "c558Gq0YQK2QUlMc".getBytes();   // 固定 IV
public static String encode(String key, String s) {
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(1, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(hoK));
    return Base64.encodeToString(c.doFinal(s.getBytes(UTF_8)), 2);   // base64
}
```

固定 IV `c558Gq0YQK2QUlMc`，PKCS5，base64。协商的全部参数都齐了。

## 请求信封：body 加密 + 签名 + 一堆 header

脱壳出来的 `HttpSecretHelper.p(httpRequest)` 是加密请求的构建器，一行行看它挂了什么：

```java
httpRequest.Ef(SecretHttpController.cff().ceM());                 // K_s
httpRequest.Ee(SecretHttpController.cff().cfi().getSecretKeyValue());  // secretKeyValue
...
builder.a(method, Utils.a(httpRequest, gson).requestBody);        // body = 加密后的
builder.fo(kjA, gson.toJson({deviceType,appVersion,reqVersion,appType}));   // X-A-REQ-HEADER
builder.fo(kig, NetAppConfig.jL());                               // X-L-JANUS-STRATEGY
builder.fo(kjB, httpRequest.ceL());                               // X-K-HEADER = secretKeyValue
String strA = a(httpRequest, url, json, body_kka);               // 签名
builder.fo(kjC, strA);                                           // X-S-HEADER = 签名
```

body 的加密在 `Utils.a` → `eA`：

```java
private static String eA(String key, String plain) {
    return new JSONObject().put("data", AES256CBC.encode(key, plain)).toString();
}
```

即 body = `{"data": AES256CBC.encode(K_s, 明文body)}`。

签名 `X-S-HEADER`（`HttpSecretHelper.a(req, url, json, body)`）：

```java
String path = url.substring(url.indexOf("lagou.com") + 9);       // "/v1/xxx"
String code = DigestUtils.al(json, path, body);                  // 见下
JSONObject o = new JSONObject();
o.put("code", code.toUpperCase());
o.put("originHeader", json);
return AES256CBC.encode(req.ceM(), o.toString());                // X-S-HEADER 也 AES 加密
```

`DigestUtils.al(strArr...)` = 把非空、非 `"{}"` 的参数拼起来，`ED` 之：

```java
public static String al(String... a) {
    StringBuilder sb = new StringBuilder();
    for (String s : a) if (!isEmpty(s) && !"{}".equals(s)) sb.append(s);
    return ED(sb.toString());
}
public static String ED(String s) {                              // SHA-256 hex
    return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(UTF_8)));
}
```

所以 `code = SHA256(json ‖ path ‖ body).hex().toUpperCase()`（json/body 为 `{}` 时跳过），`X-S-HEADER = AES(K_s, {"code": code, "originHeader": json})`。`X-K-HEADER` 就是协商拿到的 `secretKeyValue` 回显（服务器靠它认这条会话用哪个 K_s）。

整条协议合起来：

```
K_c = 随机 32-hex                       # 客户端 AES key
POST gate.lagou.com/system/agreement  body={"secretKeyDecode": base64(RSA(pubkey, K_c))}
K_s = AES.decode(K_c, resp.secretKeyValue)   # 会话 key（UUID 去掉 '-' = 32 hex）
—— 之后每个请求 ——
path = url 去掉 lagou.com 前缀
body = {"data": AES.encode(K_s, 明文body)}
X-K-HEADER = secretKeyValue
X-S-HEADER = AES.encode(K_s, {"code": SHA256(json+path+body).UPPER, "originHeader": json})
X-A-REQ-HEADER = {deviceType, appVersion, reqVersion, appType}
```

## 纯 Python 复现 + 实测

RSA 公钥从 `assets/lagou.crt` 抽出（2048 位）。AES/RSA/SHA256 都是标准原语，Python 直接写。密钥协商是免登录的，可以直接打真服务器验证：

```
$ python -c "from lagoucli.client import LagouClient; c=LagouClient(); print(c.key_agreement())"
2a6294fd-a25c-4b3e-...            # 服务器回了会话 key —— 密钥协商实测打通
```

服务器接受了纯 Python 造的 `RSA(K_c)`、回了会话 key，加密信道离设备建起来了。再用完整信封打一个业务端点（`v1/neirong/janus/app/strategies`），服务器把加密 body 解开、走到应用层，返回 `state:1003 "非法的访问"`，这不是加密/签名错（那样网关早在解密阶段就拒了），是应用层要登录态 `userToken`。加密协议这层全对了，业务数据再补一个 `userToken`（走它的短信登录，跟另一个 App 一样）即可。

## 复盘

- **加密信道 = 密钥协商 + 对称加密 + 签名，三层拆开各个击破**。协商层看「客户端 key 怎么造、怎么给服务器、会话 key 怎么回来」；对称层看 AES 的 mode/IV/padding/编码（这里 IV 是死的，最省事）；签名层看「拼什么、什么摘要、大小写」。逐层对着脱壳代码抄，不猜。
- **公钥在 assets 里**。`RSAEncoder` 从 `assets/lagou.crt` 读证书取公钥，客户端只需公钥，抽出来就行，不用逆 native。
- **会话 key 的坑：UUID 去 '-'**。服务器回的会话 key 是 36 字符 UUID 形式，AES-256 要 32 字节；去掉 4 个 `-` 正好 32 hex，跟代码里 32 字符的默认 key 对上。不去 `-` 直接报 `Invalid key size (288)`。
- **判据分层**：密钥协商能拿到会话 key = 协商层对；业务端点从「网关拒」变成「应用层要登录」= 加密+签名层对。错误码从 601（协商/网关）到 1003（应用鉴权）的变化，本身就是进度条。
