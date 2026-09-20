# 证书路径工作台 (Certificate Path Workbench)

一个纯本地、离线的 X.509 证书链构建与对比工作台。导入本地 DER/PEM 证书和多个信任锚后，
服务端枚举**所有**可行验证路径，前端逐边展示匹配证据并对比某条路径为何成功或失败。

**不访问系统证书库，不发起任何网络请求。** 内置场景夹具全部由 Node `crypto` 在内存中生成。

## 运行

```bash
npm install
npm run dev      # API http://127.0.0.1:4174 ，前端 http://127.0.0.1:4173
npm test         # vitest
npm run build    # 类型检查 + 前端构建
```

## 覆盖的场景

| 场景 | 夹具 |
| --- | --- |
| 自签名信任锚 | `root-a.pem` / `root-b.pem` |
| 交叉签名（同名同密钥、不同签发者） | `root-a-cross-signed-by-b.pem`（A1 可分别走 Root A 直连或经交叉证书到 Root B） |
| 缺少中间证书 | `leaf-missing-intermediate.pem`（Intermediate X 故意不提供） |
| 重复证书 | `leaf.pem` 与 `leaf-copy-duplicate.pem`（相同 DER 合并，来源全部保留） |
| 同名但不同密钥 | `root-a-same-name-different-key.pem`（名称匹配但签名验证失败，列为被拒绝候选） |
| 过期 | `leaf-expired.pem`（逻辑时间可调，移动到 2024 年即恢复） |
| 弱算法 | `leaf-sha1.pem`（ecdsa-with-SHA1，默认策略拒绝，可勾选允许 SHA-1） |
| 不受信锚 | `root-c-untrusted.pem` + `leaf-untrusted.pem`（在左侧把盾牌点亮提升为锚后成功） |

## 路径构建逻辑 (`src/server/crypto/pathbuilder.ts`)

- **连接条件（全部满足才算可用边）**：issuer/subject DN 严格相等 → AKI/SKI 一致检查 →
  用候选签发者公钥对上一张证书的 TBSCertificate 做真实密码学签名验证。
  仅名称相同但密钥不同的证书不会连通，而是作为"被拒绝候选"连同失败原因保留展示。
- **防循环**：DFS 维护已访问指纹集合，遇到即剪枝（`cycle-cut`）。
- **交叉签名**：枚举同时保留经交叉证书到不同锚的路径，不做提前剪枝。
- **候选排序（低分为优，全部结果保留）**：路径长度 → 算法策略惩罚（SHA-1/弱 RSA）→
  锚优先级（按导入顺序）→ 状态（trusted &lt; invalid &lt; incomplete）。
- **路径校验**：逻辑时间有效期、not_ca / keyCertSign、pathLenConstraint、RSA 最小长度、
  SHA-1 策略、签名算法支持。
- **策略 revision**：每次策略修改 revision 自增；前端在策略/时间/输入变化后将旧报告
  视觉标记为过期（变暗 + 横幅），直到重新验证。

## API

- `GET  /api/fixtures` — 内存生成的场景夹具 PEM
- `POST /api/parse` — 解析粘贴的 PEM 包
- `POST /api/validate` — 入参 `certPems[]`、`anchorPems[]`、`verificationTime`、
  `policy {minRsaBits, allowSha1}`、`policyRevision`、可选 `target`；返回完整枚举报告
