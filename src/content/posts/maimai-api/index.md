---
title: 脉脉 接口逆向——没有 per-request 签名的鉴权模型与离设备复现
summary: 与加签栈相反的一端：零 per-request 签名，鉴权只靠 access_token + u + 明文设备参数；离设备复现几乎零门槛。
created: '2026-09-02'
tags:
  - 移动安全
  - 逆向
  - 协议
  - 鉴权
  - access_token
  - RSA
  - 离设备复现
  - React-Native
venue: 看雪
target: com.taou.maimai（脉脉）v6.6.84
source: 发表文章/某职场社交App-无签名鉴权与离设备复现/职场社交App_接口逆向_看雪版.md
---

前一篇逆的是BOSS直聘，搜索接口每个请求都由 native `libyzwg.so` 出 `sp`/`sig`，离设备复现要先把加签算法啃出来。这一篇换一个职场社交 App，本想按同样的套路找它的加签栈，结果找了个遍——没有。请求的鉴权全压在 `access_token` 上，其余是一串明文设备参数。反倒省了最难的那一步。

样本 v6.6.84（`com.taou.maimai`），arm64-v8a。抓包看请求：URL query 里一长串参数（`version`/`channel`/`device`/`u`/`access_token`/`density`…），没有密文签名字段，POST 请求体是普通表单或 JSON，响应是明文 JSON。要搞清的就一件事：一条请求凭什么被服务器接受，这个「凭什么」能不能在 PC 上离设备造出来。

包体里能看到 `libnativelib_maimai.so`、`libghostlib_maimai.so`、`libdexvmp.so`（DEX VMP 壳）、一整套 React Native / Hermes、cronet。Java 层几乎每个类都挂着美团 Robust 热修的 `ChangeQuickRedirect`/`PatchProxy`，jadx 反编译出来带一层样板，但不影响读逻辑。

环境：

| 层 | 用什么 |
|---|---|
| 静态 | jadx-headless MCP（反编译 dex） |
| 复现 | 纯 Python（`requests`） |
| 验证 | 单测对拍 URL 装配 / 通用参数 / 登录 RSA |

---

## 一、请求装配的骨架

先找请求是怎么拼出来的。所有业务请求都继承一个基类 `vb.AbstractC7495`（`BaseRequest.java`），`parameters()` 用反射把请求对象的字段转成参数 map，URL 由 `api()` 给出：

```java
public abstract class AbstractC7495 {
    public abstract String api(Context context);

    public Map<String, Object> parameters() {
        Map<String, Object> map = C6563.m15554(this);   // 反射:字段名(@SerializedName)->值
        Map<String, Object> common = this.mCommonParameters;
        if (common != null) map.putAll(common);
        return map;
    }
    public String parameterString() {                    // key=Uri.encode(value)，'&' 拼接
        ...
        sb.append(entry.getKey()); sb.append('='); sb.append(Uri.encode(String.valueOf(entry.getValue())));
    }
}
```

一个具体请求长这样，只声明字段 + 给出端点，没有任何加签动作：

```java
public static class Req extends AbstractC7495 {
    public String mobile, cptoken, cpval, voice, yidun_validate, yidun_captcha_id;
    public int yidun_error_code, refresh_captcha;
    public String api(Context context) {
        return C7497.getNewApi(context, "account", "v5", "send_reg_login_code_v3");
    }
    public Map<String,Object> parameters() { /* 只 put 上面这些业务字段 */ }
}
```

端点由 `vb.C7497.getNewApi(module, version, name)` 拼，规则就是路径拼接：

```java
public static String getNewApi(Context context, String module, String version, String name, String base) {
    StringBuilder sb = new StringBuilder();
    sb.append(base);                       // NetworkConstants.NEW_BASE_URI = https://open.taou.com/maimai
    if (!empty(module))  sb.append("/").append(module);
    if (!empty(version)) sb.append("/").append(version);
    sb.append("/").append(name);
    C6526.m15418().mo7957(sb, context);    // <- 关键:这一步往 URL 追加通用参数
    return sb.toString();
}
```

`https://open.taou.com/maimai/<module>/<version>/<name>`，最后那句 `mo7957(sb, context)` 是唯一往 URL 里加东西的地方。如果有签名，只可能在这里。

---

## 二、通用参数层：把签名找了个遍，没有

`C6526.m15418()` 走 ARouter 拿到 `IApp` 服务，`mo7957` 的实现在 `tl.C6998`，转一手到 `df.C2665.m11054`。这个方法就是通用参数装配器，把设备 / 会话 / 鉴权参数全拼进 URL query：

```java
public static void m11054(StringBuilder sb2, Context context) {
    LoginInfo loginInfo = LoginInfo.getInstance(context);
    sb2.append(sb2.indexOf("?") >= 0 ? "&" : "?");
    sb2.append("version=").append(GlobalConstants.VERSION_NAME);
    sb2.append("&ver_code=android_").append(GlobalConstants.VERSION_CODE);
    sb2.append("&channel=").append(GlobalConstants.getChannel());
    sb2.append("&vc=").append(Uri.encode(GlobalConstants.MM_SYSTEM_INFO));
    sb2.append("&net=").append(C6794.f19377);
    sb2.append("&appid=3");
    sb2.append("&device=").append(Uri.encode(GlobalConstants.MM_DEVICE_INFO));
    sb2.append("&udid=").append(Uri.encode(C6544.m15448()));
    sb2.append("&isEmulator=").append(GlobalContext.getIsEmulator() ? "1" : "0");
    sb2.append("&rn_version=").append("0.69.0");
    sb2.append("&android_id=").append(Uri.encode(PrivacyDataManager.INSTANCE.getAndroidId()));
    m11055(sb2, "&oaid=", C5930.f17561);
    m11055(sb2, "&u=", String.valueOf(loginInfo.getIdentity()));       // uid
    m11055(sb2, "&access_token=", String.valueOf(loginInfo.accessToken));
    sb2.append("&density=").append(...);
    sb2.append("&screen_width=").append(...);   sb2.append("&screen_height=").append(...);
    sb2.append("&launch_uuid=").append(Uri.encode(GlobalContext.getLaunchUuid()));
    sb2.append("&session_uuid=").append(Uri.encode(...));
    // ...
}
```

从头读到尾，没有 `sign` / `sig` / `sp`，没有对参数排序后做 MD5，没有把 body 送去哈希，没有时间戳参与的校验串。全是明文的设备指纹 + `u` + `access_token`。`m11055(sb, "&k=", v)` 只是「v 非空才追加」的小工具，也不做任何编码或哈希。

再确认这些值本身不是伪装的签名：

```java
public static final String MM_DEVICE_INFO = Build.MANUFACTURER + " " + Build.MODEL;   // "Xiaomi 22011211C"
static { MM_SYSTEM_INFO = "Android " + Build.VERSION.RELEASE + "/" + Build.VERSION.SDK_INT; }  // "Android 13/33"
```

`device`、`vc` 就是明文机型和系统版本。为排除签名藏在别处，把 okhttp 拦截器链也过了一遍：`com.taou` 下实现 `Interceptor`（混淆成 `tt.InterfaceC7189`）的只有三个——urlconnection 兼容垫片、只对 `update`/`update_bg` 两个端点补参数的 `AppendPostParamInterceptor`、异常处理拦截器。没有一个补签名头。请求体也没有签名字段。

结论落定：这个 App 的请求鉴权 = `access_token` + `u`，外加一组给风控看的明文设备参数，全程靠 TLS。签名这一层根本不存在。

---

## 三、唯一的 native 加密在登录

`libnativelib_maimai.so` 的 Java 封装 `com.taou.maimai.nativelib.NativeLib` 只有三个 native 方法：

```java
public final class NativeLib {
    static { C6951.m16038("nativelib_maimai"); }
    public final native String getKey();
    public final native Object getAndroidId(ContentResolver contentResolver);
    public final native Object getRunningAppProcesses(ActivityManager activityManager);
}
```

`getAndroidId` / `getRunningAppProcesses` 是风控绕 hook 的设备读取。`getKey()` 返回一个字符串 key。追它的调用点，六处里两处叫 `encrypt`，其中登录的 `verifyRegLoginCodeV2` 是这样用的：

```java
if (pwdLogin) {
    String value = this.password.getValue();
    req.epassword = C6584.m15599(value, d.f24624a, NativeLib.f7005.getKey());
}
```

`d` 是 alipay SDK 的 `com.alipay.sdk.m.n.d`，`d.f24624a = "RSA"`。`C6584` 是 `DigestUtils`，它的算法分派里 RSA 分支：

```smali
new-instance v3, Ljava/security/spec/X509EncodedKeySpec;
invoke-static {key, 2}, Landroid/util/Base64;->decode(...)            # key = getKey() 的 base64
invoke-static {"RSA"}, Ljava/security/KeyFactory;->getInstance(...)
invoke-virtual {...}, Ljava/security/KeyFactory;->generatePublic(...) # X.509 公钥
const-string v3, "RSA/ECB/PKCS1Padding"
invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(...)
... Cipher.init(ENCRYPT, pubkey) ; doFinal ; Base64.encodeToString(..., NO_WRAP)
```

即 `epassword = base64(RSA/ECB/PKCS1(pubkey = getKey(), password))`。`getKey()` 返回的是一段 RSA **公钥**（X.509 DER 的 base64），公钥不是机密，抽一次就能用。而且这只在密码登录时用——短信验证码登录那条路径不加密：

```java
// MMVerifyRegLoginCode.Req 的字段:短信码走 code，密码走 epassword
public String code;        // 短信验证码,明文
public String epassword;   // 密码,RSA 加密
public String reg_way = "1"; public int dev_type = 3, info_type = 2, new_fr = 1;
```

所以短信验证码登录整条链路不碰任何 native 密钥，纯参数拼装就能复现。

---

## 四、端点族与响应格式

`C7497` 里一排 `get*Api` 把模块前缀固定下来，端点族一目了然：

```
account/v5/*     登录注册    feed/v5|v6/*   信息流
gossip/v3/*      职言        contact/v3|v5/* 人脉
user/v3|v4|v5/*  用户        job/v3、talent/v3、tools/v3、imad/*
```

登录两步，都从请求 POJO 抄得到（注意 `send` 没有 `usePost()` 覆写，是 GET；`verify` 覆写了 `usePost()=true`，是 POST）：

```
GET  account/v5/send_reg_login_code_v3    mobile [+网易易盾字段] -> 响应带 token
POST account/v5/verify_reg_login_code_v3  mobile, token, code, reg_way=1, dev_type=3,
                                          info_type=2, new_fr=1 (+ &need_script=1) -> access_token + uid
```

`verify` 的 `api()` 还有个细节：它把 `&need_script=1` 直接拼在没有 `?` 的路径尾巴上，之后通用参数层才补 `?`，于是 wire 上是 `.../verify_reg_login_code_v3&need_script=1?version=...`。看着别扭，但 App 就是这么发的，复现照抄。

响应统一是 `BaseResponse`（`vb.C7496`）：

```java
public class C7496 {
    public int code = -1;
    public int error_code;
    public String error_msg;
    public String result;
    public boolean isSuccessful() { return "ok".equalsIgnoreCase(result) || code == 0; }
}
```

`code == 0` 或 `result == "ok"` 为成功，错误在 `error_code`/`error_msg`。响应体是明文 JSON，不用解密。

---

## 五、离设备复现：一条请求就够

有了上面几点，离设备发请求就是把 URL 按 `getNewApi` + `m11054` 拼出来。通用参数层里 `Uri.encode` 用的是 Android 单参重载，保留 `A-Za-z0-9` 和 `_-!.~'()*`，其余按 UTF-8 转 `%XX`（大写），空格 `%20`。这点要照 Android 实现，不能用 Python 默认 `quote`：

```python
_URI_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-!.~'()*")
def uri_encode(s):
    out = []
    for ch in str(s):
        out.append(ch if ch in _URI_SAFE else "".join("%%%02X" % b for b in ch.encode("utf-8")))
    return "".join(out)
```

一条 GET 装配出来（`user/v4/settings`，会话参数用占位值）：

```
https://open.taou.com/maimai/user/v4/settings?version=6.6.84&ver_code=android_60684
&channel=develop&vc=Android%2013%2F33&push_permit=0&net=wifi&open=icon&appid=3
&device=Xiaomi%2022011211C&udid=udid1&is_push_open=0&isEmulator=0&rn_version=0.69.0
&launched_by_user=1&android_id=aid1&u=12345678&access_token=AT_demo&density=3.0
&screen_width=1080&screen_height=2340&launch_uuid=...&session_uuid=...
&has_read_contacts_permission=0
```

`access_token` + `u` 是唯一从登录设备取一次的账号态输入，其余设备参数从抓到的那条请求 query 里直接抄。因为没有签名，同一份 session 可以重放任意读端点——把请求装配封装成一个 CLI，`mm get <path>` 打任何 `/maimai` 下的接口就行。整套复现（端点构建 `api.py`、通用参数 `common.py`、登录 RSA `crypto.py`、装配发送 `client.py`、登录 `login.py`）加确定性单测放在 maimai-cli 仓库里，端点 URL / 通用参数装配（断言里显式验证「不含任何签名参数」）/ 登录 RSA 往返都对拍通过。

登录同理：`send_reg_login_code_v3` 发码（man/machine 是网易易盾，离设备要先解出 `yidun_validate` 传进去），`verify_reg_login_code_v3` 拿 `access_token` + `uid` 写回 session。之后所有读接口都用这份 session。

---

## 六、动态验证：真机上 hook 一下 m11054

静态读代码得出「无签名」，还是拿真机流量坐实一下。Pixel 6 / Android 16，art-runtime-srv 17.16.4（Morphida 反检测那套，进程名被遮，按 PID 或 spawn 走）。frida-17 断代，`Java` 桥不再默认全局，脚本要 `import Java from 'frida-java-bridge'` 再 `frida-compile` 打包。

hook 点选通用参数装配器 `df.ൡ.അ`（就是 `C2665.m11054`，运行时类名是混淆的 Unicode）。它把参数拼进传入的 StringBuilder，调完原方法读一下 `sb.toString()` 就是这条请求的完整 query：

```
Java.use('df.ൡ')['അ'].overload('java.lang.StringBuilder','android.content.Context')
  .implementation = function (sb, ctx) {
    this['അ'](sb, ctx);
    var url = '' + sb.toString();
    send({ url: url, hasSig: /[?&](sign|sig|sp|signature)=/.test(url) });
  };
```

spawn 起来抓匿名启动流量（不登录、不发短信），一批 config 请求都从这里过，输出如下：

```
url=https://open.taou.com/maimai/pbs/check_version?version=6.6.84&ver_code=android_60684
    &channel=MyAPP&vc=Android%2016%2F36&push_permit=1&net=wifi&open=icon&appid=3
    &device=Google%20Pixel%206&udid=fd82870c-…&is_push_open=1&isEmulator=0&rn_version=0.69.0
    &launched_by_user=1&android_id=&webviewUserAgent=…&density=2.625&screen_width=1080
    &screen_height=2209&launch_uuid=…&session_uuid=…   hasSig=false
url=https://api.taou.com/sdk/global/config?…&new_device=0&rom_version=16&rom_name=GOOGLE
    &webviewUserAgent=…&vender=google&install_uuid=…&language=_&package_name=com.taou.maimai&…  hasSig=false
url=https://open.taou.com/maimai/pbs/global_config?…                                            hasSig=false
url=https://maimai.cn/sdk/global/share_config?…                                                 hasSig=false
```

每条 `hasSig=false`，参数集和顺序跟静态读出来的 m11054 一字不差。`sdk/global/config` 那条还多带了 `new_device/rom_version/rom_name/vender/install_uuid/language/package_name`——正是 m11054 里对这个路径的条件分支，动静态对上。

再看 native key 和登录。hook `NativeLib.getKey()`，走一次密码登录（假号假密码，本地算 epassword 时触发，登录被服务器拒、不给任何人发短信），拿到：

```
GETKEY  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbJGJuNnD/h1Cnrjw4rwjQ9JXZssXgpsjPrhPz…IDAQAB  (len=216)
URL     https://open.taou.com/maimai/account/v5/verify_reg_login_code_v3?version=6.6.84&…
        &session_uuid=…&need_script=1   hasSig=false
```

`MIGf…IDAQAB` 是标准的 base64 X.509 SubjectPublicKeyInfo，`AQAB` 就是指数 65537，128 字节模长——1024-bit RSA 公钥，坐实了 `getKey()` 返回公钥、只用来加密登录密码这一判断。

顺带纠了个静态时看走眼的细节：`verify` 的 `need_script=1` 是拼在通用参数**之后**（`verify_reg_login_code_v3?<common>&need_script=1`），不是塞在路径尾巴上。原因前面说过——`getNewApi` 返回时通用参数已经拼好了，`api()` 再往整串 query 后面追加。离设备复现按抓包这个顺序对齐即可。

## 七、复盘：和 BOSS 那套的对照

同样是国内头部 App 的接口逆向，这两个的安全模型正好是两端：

- **BOSS 把成本压在每请求加签**：`sp`/`sig` 出自 native `libyzwg.so`，签名输入含 body 的 CRC，响应还要 native 解密。离设备复现的门槛是把 native 算法（内嵌盐 + 混淆 RC4 + LZ4）啃出来。
- **这个职场社交 App 把成本压在账号态**：请求本身零签名，鉴权就是 `access_token` + `u` 走 TLS。离设备复现的门槛几乎为零——抓一次 session 就能重放，真正的门槛前移到「怎么拿到并保住 `access_token`」（登录风控、网易易盾、设备指纹一致性）。

两种取舍各有代价。前者逆向一次成本高、但一劳永逸；后者请求层几乎裸奔，安全性全靠 token 的下发与风控兜底，一旦 token 泄漏，服务端只能靠设备指纹参数和行为风控识别异常，而那些参数在本例里都是明文、可随意伪造。

- **先证否再动手**：本来准备找加签栈，`getNewApi` → `m11054` 读完确认没有签名，比假设有签名再去逆一个不存在的东西省时间。判据也硬——把通用参数装配器逐行读完、把 okhttp 拦截器链过一遍，两处都没有哈希/排序/body 摘要，才敢下这个结论。
- **native 里出现 `getKey` 不等于有请求签名**：这里的 `getKey()` 是 RSA 公钥，只服务于登录密码加密，跟每请求鉴权无关。追调用点（六处，两处 `encrypt`，落在登录和 JS bridge）比看方法名猜用途可靠。
- **短信验证码登录是最干净的复现入口**：不碰 native 密钥，`send` + `verify` 两个 HTTP 请求就能离设备签发 `access_token`。

### 关键结论与端点（v6.6.84 arm64-v8a）

```
base   = https://open.taou.com/maimai
url    = getNewApi(module, version, name) + "?" + m11054(通用参数) [+ "&" + 业务参数]
鉴权   = access_token + u(uid)              # 明文 query,无 per-request 签名
通用参数 = version/ver_code/channel/vc/device/udid/android_id/oaid/u/access_token/density/screen_*/launch_uuid/session_uuid ...(全明文)
登录   = GET  account/v5/send_reg_login_code_v3   (mobile + 网易易盾)
         POST account/v5/verify_reg_login_code_v3 (mobile+token+code, reg_way=1,dev_type=3,info_type=2,new_fr=1,need_script=1)
密码加密 = epassword = base64(RSA/ECB/PKCS1(pubkey=NativeLib.getKey(), password))   # 公钥,非机密;短信登录不用
响应   = 明文 JSON,code==0 或 result=="ok" 为成功,错误在 error_code/error_msg
native = NativeLib.{getKey(RSA公钥), getAndroidId, getRunningAppProcesses(风控设备读取)}
```

Uri.encode 用 Android 单参重载（保留 `_-!.~'()*`，空格 `%20`），复现时别用 Python 默认 `quote`，否则 `~`、空格编码不同、参数对不上。
