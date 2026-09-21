# 证书链路径工作台（Certificate Chain Path Workbench）

一个**完全离线**的证书路径构建/验证教学工作台：导入本地 DER/PEM 证书与多个信任锚，
服务端枚举从目标证书到信任锚的**所有**可行验证路径，前端逐条展示每一条边的
名称 / AKI-SKI / 签名匹配证据与失败约束，并比较某条路径为何成功或失败。

- 不访问系统证书库（不用 `X509Certificate.checkIssued`、`tls.rootCertificates` 等）
- 不发起任何网络请求（无 CRL/OCSP/AIA）
- 零第三方依赖：仅用 Node 内置 `http` / `crypto`，前端为原生 HTML/CSS/JS，无构建步骤

## 运行

```bash
node src/server/index.js
# 打开 http://127.0.0.1:4174
```

需要 Node ≥ 18（开发于 Node 20）。首次启动会在内存中用本地生成的 RSA/EC 密钥铸造夹具 PKI。

## 测试

```bash
node --test test/
```

35 个测试覆盖 DER 编解码、X.509 解析与签名验证（与 OpenSSL/Node `X509Certificate` 交叉校验）、
全部路径场景、策略 revision 行为以及 HTTP API。

## 能力

### 路径构建（`src/server/pathBuilder.js`）
- **连接证据三段式**：issuer/subject 规范化 DN（附 DER 字节是否一致）→ AKI/SKI → 密码学签名验证。
- **防环**：以证书指纹记录已访问节点，签发环（两张 CA 互签）被检出并剪枝，不做无限遍历。
- **同名交叉签名**：同主体名不同密钥的候选都枚举；名称相同但 AKI/密钥不对应或验签失败的连接
  进入「被拒绝的候选边」，保留证据。
- **缺中间证书 / 重复证书 / 孤儿 / 自签名非锚**：分别终止于明确的终态；重复 DER 指纹去重。
- **枚举不丢结果**：DFS 记录全部终态（到锚有效、到锚但约束失败、无法到锚），排序只重排不删除。

### 候选排序（保留其他结果）
有效路径优先；同分时按**锚优先级顺序**（可在界面上下调整）→ 路径更短 →
算法更强（SHA-1/RSA-1024 扣分）。每条路径带排序分与锚优先级。

### 验证绑定（逻辑时间 + 策略 revision）
- **逻辑验证时间**：有效期检查绑定到请求给定的时刻，而非当前墙钟时间（可演示「早于过期时有效」）。
- **策略 revision**：`permissive` rev 2（接受 SHA-1/RSA-1024、不强制 CA 位/pathLen）、
  `standard` rev 5（默认）、`modern` rev 8（额外要求 keyCertSign 与 SKI/AKI）。
- 结果对象带 `binding {policyId, policyRevision, verifyAt, computedAt}`；
  前端对输入、锚、时间或策略的任何变更计算输入指纹，旧结果立即降透明度并显示
  「旧结果 · 已过期」丝带与顶部横幅，直到重新构建。

### 逐边 / 逐节点展示
- 每条边：`name`、`aki_ski`、`signature`、`signature_algorithm_policy`、
  `issuer_key_strength`、`path_len` 的通过/警告/失败明细。
- 每个节点：有效期、basicConstraints、key usage（末端实体不要求 CA 位；锚证书仅警告不失败）。
- 右栏汇总所有被拒绝的候选边及失败原因（签名失败、AKI/SKI 不匹配、策略否决、环路剪枝）。

## 预置场景（10 个，`src/server/fixtures.js`）

| 场景 | 说明 |
|---|---|
| `cross` | 交叉签名：同主体同密钥的旧根存在自签名与被主根交叉签名两张证书，枚举出一真一不受信两条路径 |
| `gap` | 缺少中间证书（导入缺失 CA 后即变有效） |
| `dup` | 同一 DER 重复导入，去重且无伪路径 |
| `twin` | 同主体名不同密钥的两张 CA，仅一张能验签 |
| `expired` | 过期叶子；切换逻辑时间可翻转结论 |
| `untrusted` | 孤儿叶子与未知自签名根 |
| `legacy` | SHA-1 + RSA-1024：仅宽松策略接受 |
| `pathlen` | 根 pathLen=0，其下非自签发中间 CA 违反约束 |
| `loop` | 两张 CA 密码学上互签构成真环，构建器必须剪枝 |
| `all` | 全量工作台 |

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | `{ok,offline}` |
| GET | `/api/policies` | 策略列表及 revision |
| GET | `/api/fixtures` | 预置证书（base64 DER）与场景 |
| POST | `/api/parse` | `{certs:[PEM/base64…]}` 解析 + 去重 |
| POST | `/api/build` | `{certs, anchors, anchorFingerprints, anchorOrder, target, policyId, verifyAt}` 枚举+验证 |

## 代码结构

```
src/shared/der.js          手写 DER/BER TLV 编解码（OID/时间/整数/序列…）
src/shared/x509.js         X.509 解析（DN/有效期/SPKI/SKI/AKI/BC/KU）+ 签名验证 + PEM/DER
src/server/certBuilder.js  本地造证（RSA/EC 密钥、SKI/AKI/BC/KU、SHA-1/SHA-256）
src/server/fixtures.js     10 个夹具场景的离线 PKI
src/server/policy.js       三档策略及 revision
src/server/pathBuilder.js  图构建、候选边、DFS、环检测、pathLen、排序、终态
src/server/index.js        零依赖 HTTP + 静态文件
src/client/                原生前端（导入/锚排序/策略时间绑定/逐边证据/过期标记）
test/                      node:test 自动化测试
```
