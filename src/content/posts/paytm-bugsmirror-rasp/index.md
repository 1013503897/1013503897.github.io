---
title: Paytm · BugsMirror Defender RASP 攻坚——KPM 无痕 + 一字节破 spin
summary: >-
  BugsMirror Defender RASP：KPM 无痕破 code-CRC 硬 kill；进程内自 dump 逆检测面；SIGPROF 采样定位
  spin PC，一字节写 flag 破静默拒服。
created: '2026-07-25'
tags:
  - 移动安全
  - 逆向
  - RASP
  - Paytm
  - BugsMirror
  - KPM
  - code-CRC
  - 反调试
venue: 看雪
target: net.one97.paytm（BugsMirror Defender libdefender.so）
source: 发表文章/Paytm-BugsMirror-RASP攻坚/paytm_rasp逆向_看雪版.md
---

> 目标是一个印度头部支付 app 的 native RASP,厂商 **BugsMirror Defender**(`libdefender.so` / `paytmdefender.bugsmirror.com`,FIPS crypto)。攻坚分三层:内核无痕注入破 code-CRC 硬 kill → 进程内自 dump + 静态分析逆清检测面 → SIGPROF 采样定位 spin PC、逆出 flag-wait 自环、一字节破 spin。本文重方法论。
>
> **免责**:仅技术交流。确切偏移、flag 地址、patch 常量一律略去或泛化,避免被直接照搬对抗真实支付 app 的安全机制。请勿用于任何违规用途。

---

## 0x00 背景与死法分诊

先把"这是不是 RASP"确认掉。空注入(只挂隐蔽载体、不改任何业务逻辑)先验:

- 直接注入 → 加载期 SIGSEGV;
- 无 `am_crash` / 无 tombstone / 无 Java FATAL;
- 死法固定(启动数秒内)。

三条都指向环境检测,不是业务 bug。native 层可疑库 `libcachehandler.so`(壳,真身 `org.npci...OfflineNativeDefender`)。

---

## 0x01 第一层:KPM 无痕注入破 code-CRC

### 症状与根因

直接注入秒崩的根因:注入框架(这里是 Vector/LSPlant)默认用 **Dobby inline hook** 改 `libart` 的 `.text` 来挂 ART 方法。RASP 有 **code-CRC**:运行时对关键 so 的代码字节算校验和自校验,inline hook 改的那几个 trampoline 字节被抓。

### 处置:内核 region-clone 无痕

把 hook 从"改目标 .text"换成**内核级 PTE/UXN region-clone**:克隆一份代码页区、在**克隆页**上打 hook,目标原文页一字节不改;通过 PTE 把执行重定向到克隆页。于是:

- RASP 的 code-CRC 读的是**原文页** → 干净;
- 实际执行走**克隆页** → 已 hook。

落地上是把目标进程 gate 进无痕后端(keyless APatch 下 `persist.kpmhook.target` 是 `default_prop`,shell setprop 被 SELinux 拒,先 `magiskpolicy --live "allow shell default_prop property_service set"` 再 setprop)。

### 判据

```
gate 前:logcat 一大堆  Dobby : ----- [DobbyHook:0x...] -----
gate 后:DobbyHook = 0 次  且  "KPM inline hook failed" = 0 次
```

即 libart `.text` 全走无痕路径。结果:**SIGSEGV 消失,app 干净渲染开屏、越过 30s 杀窗口**。

> 但 code-CRC 只是这套 RASP ~20 项检测里的 1 项。app 随即**卡开屏**,主线程 100% CPU。

---

## 0x02 卡开屏的分诊:不是崩溃,是静默 spin

| 观测 | 判断 |
|---|---|
| 无 crash/tombstone/FATAL | 优雅处置 |
| 活过 30s | 硬 kill 那路已压住 |
| 主线程 `state=R wchan=0 syscall=running` | **纯用户态忙循环**(非 IO/锁/网络阻塞) |
| 多个单线程子进程 `ppid=主`,`comm` 伪装成 `DefaultDispatch`/`pool-XX-thread` | RASP fork 的看门狗 mesh + 线程名伪装 |

结论:RASP 判环境脏后**让主线程永久 busy-spin**(不 kill、避免暴露检测点)。这是一种"静默拒服"。

---

## 0x03 第二层:进程内自 dump + 逆清检测面

### 自 dump 绕 non-dumpable

RASP 用**裸 syscall**(`svc`/`syscall(__NR_openat/ptrace)`)读检测面,libc 层 hook(`openat`/`ptrace`/`popen`)**全零命中**。`/proc/<pid>/mem` 跨进程 dump 被 non-dumpable 挡。

破法:**注入体在进程内自己 dump 自己**。读 `/proc/self/maps` 找目标 so 各可读段,`memcpy` 自身地址空间(此时 `.text` 已 dlopen 期解密)写到 **app 自己的数据目录**(`/data/data/<pkg>/`,untrusted_app 唯一可写处),再 root 拉出。

意外收获:**这套 RASP 字符串未加密**,`strings` 直接出全貌:

- 身份:`libdefender.so`、`paytmdefender.bugsmirror.com`;
- ~20 个 `Is*CheckEnabled`(`IsDeveloperOption/IsOemUnlocked/IsStrongDeviceIntegrity/IsUsbDebugging/IsVpnDetection/IsPacketSniffing…CheckEnabled`),读加密的 `DefenderConfigFile`;
- 消息:`"Your device is rooted!"`、`"Active USB connection detected"`、`"App integrity check failed: cloning or repackaging detected"`;
- 看门狗 `checkForRuntimeCodeInjectionContinuously`、root 用 `which %s`、服务端 `verifyAndLogUser`。

### dump↔VA 映射(让静态分析有意义)

拼接的段 dump,file offset ≠ VA,ADRP/xref 全错位。对齐办法:**用一段已知 VA 的字节序列在 dump 里 find**。早前动态抓到某函数 `fnB` 在 VA-off `0x179c00` 的字节,在 dump 里 `find` 到它的位置,相减即得该连续区的 `DELTA`:

```python
delta = dump.find(fnb_bytes) - 0x179c00     # 得 0x18e000
# 之后:dump_off = VA_off + DELTA,capstone 可精确定位任意 VA-off
```

### verdict 架构(capstone 统计)

扫 code 段统计 `bl` 目标频次,几个 choke point 就露出来:

- **verdict-report 函数**被调 **180 处**(pass+fail 都上报;错误码 `41002-IST1/2/3` 设备完整性、`70011-70018`、`BusinessIntegrityException`);内部 `ldarb` 原子读一串全局 byte 标志,把 verdict 累积进**全局状态结构**。
- **kill 路径全汇聚到一个 helper(`fn_B`),仅 2 处调用** = 窄 choke(patch 一处灭所有 native kill)。
- 注意 `In Core Integrity check FIPS`(自 CRC)→ **直接改它自己 .text 有反噬**,严格该走无痕 patch。
- `0x188xxx` 被调数千次的那批别误判成混淆 helper。反汇编一看是标准 **PLT 桩**(`adrp x16; ldr x17,[x16,#off]; br x17`)。**这套 RASP 不是 VMP、也没有重度控制流平坦化**,是正常编译的 C++(vtable 多态检查),直接可 patch。

---

## 0x04 第三层:SIGPROF 采样 → 逆出 flag-wait 自环 → 一字节破 spin

### 采样定位纯用户态 spin PC

`debuggerd -b` 被 RASP 干扰(`tombstoned reported failure`),ptrace 被反调试(检测 TracerPid)。改用 **SIGPROF 采样**:`ITIMER_PROF` 按 CPU 时间触发、投给烧 CPU 的线程:

```c
sigaction(SIGPROF, {.sa_sigaction=prof_handler, .sa_flags=SA_SIGINFO}, 0);
setitimer(ITIMER_PROF, {.it_interval={.tv_usec=300000}, .it_value={.tv_usec=300000}}, 0);
// prof_handler: pc = ((ucontext_t*)uc)->uc_mcontext.pc; dladdr(pc) → so + off
```

采样**稳定命中同一 PC**,落在 `libcachehandler` 内(native,**不是** JIT Java;纠正了先前猜测)。稳定同 PC = 极小忙循环。

### 逆出自环

用 `DELTA` 从 dump 反汇编该 PC 那一小段(去具体地址):

```asm
    adr   x8, <clean-flag 地址>       ; BSS 里一个标志位字节
L:  ldarb w9, [x8]                    ; ← 采样命中的 spin PC:原子读
    tbz   w9, #0, L                   ; (flag & 1)==0 → 跳回自己
    ldarb w8, <另一个 flag>           ; 置位后才继续
```

即:

```c
do { w9 = *clean_flag; } while ((w9 & 1) == 0);   // 死等看门狗判 clean 置 bit0
```

主线程 gate 在看门狗置的一个 flag byte 上;环境脏 → 看门狗不置 → 永远转。

### 一字节修复

注入体后台线程持续把该 flag 的 bit0 置 1(持续=防看门狗清回):

```c
*(volatile uint8_t*)(find_lib_base("libcachehandler") + FLAG_OFF) |= 1;
```

**设备实测**:
- 主线程 `R/100%CPU` → **`S / do_epoll_wait`**(正常 Looper 空闲);
- 焦点 Activity 开屏 → app 主框架 Activity;
- 正常初始化(音频/GC/Play Integrity 跑完)。**越过开屏。**

---

## 0x05 边界与方法论

### 诚实边界

USB 直连 root 开发机上,BugsMirror 多因子(USB 调试 / 开发者选项 / OEM 解锁 / root)**独立触发、与注入无关**。破 code-CRC + 写 flag 让 app **进 UI 层**;但后面有:
- Java 层路由 / 完整性门(app 停在透明中转 Activity);
- **服务端 attestation**(`verifyAndLogUser` + Google **Play Integrity**),设备指纹在服务器判定,**本地不可达**。

→ **"进 UI" 可达;"登录/支付正常" 受服务端 attestation 限制,本地不可达。** 防护有没有用,看它有没有盖住你的攻击路径,不看算法多硬。

### 可复用方法

1. **纯用户态 spin 抓不到栈** → `ITIMER_PROF` + `uc_mcontext.pc` 采样(躲 ptrace 反调试)。
2. **加密壳代码** → 进程内自 dump(注入体自读解密内存,写 app 目录),躲 non-dumpable / 反 dump。
3. **拼接 dump 对齐 VA** → 已知 VA 的字节序列在 dump 里 find 反推 DELTA。
4. **choke-point 思维** → 别逐条破 N 项检测;找 verdict 汇聚点(kill helper / clean-flag byte),一处顶一片。RASP 的"静默 spin"恰把汇聚点暴露成一个可写 flag。
5. **先判 VMP/CFF 还是普通编译** → `bl` 频次 top 项若是 `adrp+ldr+br` = PLT 桩,不是混淆;正常 C++ 直接可 patch。

---

一个"卡开屏"最后收敛成一条 `ldarb+tbz` 自环和一个字节的写入。RASP 对抗的核心从来不是"和检测硬刚",而是**找到它把裁决落到哪个可写的点上**。
