# 本地安全更新客户端（离线、纯标准库）

从零实现的本地安全更新客户端：接收一个**双镜像更新包**（根信任文档、通道快照、
目标清单、文件摘要），按租户维护防回退水位，只用 SQLite 做原子发布与固定版本只读查询。
不访问网络、不连接任何真实软件仓库或服务，全部输入由本仓库自行合成。

- 平台：Windows 原生 Python 3.12，仅标准库（`sqlite3`/`hashlib`/`hmac`/`json`/`threading`），纯 CPU。
- 签名是**模拟验签**：HMAC-SHA256 绑定「签名者代数 + 规范文档摘要 + 文档类型 + 租户 + 一次性 nonce」。
  它不是真实公钥密码学，但保留了本任务全部需要区分的性质（见下文「模拟签名」）。

---

## 1. 运行方式

```bash
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

辅助工具（不参与验收，但可复现 README 中的表格）：

```bash
python tools/generate_cases.py     # 重新生成 cases.json（确定性）
python tools/trust_table.py        # 打印跨两次根轮换正例 + 独立信任验证表
python tools/trust_table.py --json # 同上，机器可读
```

`python -m solution` 退出码：

| 退出码 | 含义 |
|---|---|
| 0 | 全部用例的实际结果与 `expect` 一致 |
| 1 | 至少一个用例不符（`result.json` 内含逐步骤差异） |
| 2 | 输入文件不可读/不可解析，或命令行参数缺失 |

---

## 2. 更新包格式（双镜像）

```
package/
  index.json            # 唯一的清单：租户、两个镜像目录、所有相对路径
  mirror-a/<rel_path>   # 文档与载荷文件
  mirror-b/<rel_path>   # 必须与 mirror-a 逐字节一致
```

`index.json`：

```json
{
  "format": "simupd-package/1",
  "tenant": "acme-updates",
  "mirrors": ["mirror-a", "mirror-b"],
  "documents": ["roots/root-0002.json", "snapshots/stable-0001.json", "targets/svc-a-0001.json"],
  "files": ["app/services/svc-a.bin"]
}
```

规则：

1. **只信路径，不信内容**。`documents`/`files` 里的每个路径都按仓库路径规范化校验
   （见第 3 节），解析后必须仍落在包目录内，否则 `E_PATH_ESCAPE`。
2. **双镜像必须逐字节一致**。任一镜像缺文件 → `E_MIRROR_MISSING`；两镜像字节不同 →
   `E_MIRROR_DIVERGENCE`（错误详情给出每个镜像的 sha256）。
3. **文档必须是规范 JSON 字节**：键排序、无多余空白、UTF-8、`ensure_ascii=False`。
   磁盘上的字节就是被签名的产物，杜绝解析器与签名器对同一文档产生不同理解。
4. 同一文档（按 `doc_type + 身份 + version`）在包内只能出现一次。

---

## 3. 仓库路径规则

合法仓库路径满足：

- 非空、相对路径（不得以 `/` 开头，不得含盘符），不含 `\` 与 NUL；
- 按 `/` 切分后没有空段、`.`、`..`；
- 每段匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`；
- `posixpath.normpath(path) == path`（即已是规范形式）。

角色授权按**整段前缀**匹配：前缀 `app/services` 授权 `app/services/x`，但**不**授权
`app/servicesevil/x`。这是独立的预期场景之一（`tests/test_pipeline.py::
test_target_path_prefix_is_not_string_prefix`）。

---

## 4. 三类文档与角色策略

三种签名文档：`root`、`snapshot`、`target`。**只有根文档携带密钥材料**；快照与目标
永远用「已确认根」的 keyring 验签，绝不用文档自带的任何材料。

根的 `roles` 恰好包含三个**互斥**角色：`root`、`snapshot`、`target`。角色策略：

```json
{
  "threshold": 2,
  "holders": {"holder-id": ["key-id", ...]},
  "revoked": [{"key_id": "k1", "gen": 1}],
  "tags": ["core"] 或 ["*"],
  "paths": ["app", "lib/core"] 或 ["*"]
}
```

- **席位按持有人计**：同一持有人提交多个密钥只占一席；完全相同的签名记录
  （同 `key_id + gen + nonce`）计入 `duplicates_skipped`，不重复计票。
- **吊销按代数**：`(key_id, gen)` 在 `revoked` 中被丢弃；同密钥其它代数仍有效。
- **角色互斥**：同一 root 内，任一持有人、任一密钥都不得同时出现在两个角色里，
  否则 `E_ROLE_EXCLUSIVITY`。
- **root 角色必须对全部标签和路径授权**（`tags == ["*"]` 且 `paths == ["*"]`）。
- `keyring` 必须恰好等于三个角色引用的密钥集合。

### 4.1 根轮换：双阈值 + 互斥持有人

新根 `v = 旧根版本 + 1`，且 `previous_digest == 旧根的载荷摘要`。轮换必须**同时**满足：

- 用**旧根**的 root 角色验签新根，达到旧根阈值；
- 用**新根**的 root 角色验签同一份新根，达到新根阈值；
- 两套法庭由**不同持有人**组成（同一人不能既代表旧根又代表新根）。

这是一道两需求的 Hall 可行性判定：设旧侧持有人集合 `A`、新侧 `B`、阈值 `k_old`/`k_new`，
可行当且仅当

```
|A| >= k_old   且   |B| >= k_new   且   |A ∪ B| >= k_old + k_new
```

可行时按「先独占、后共享」的确定性顺序分配席位，因此同一输入永远得到同一张席位表。
失败原因精确区分：`old_threshold` / `new_threshold` / `holder_overlap`，分别映射到
`E_ROOT_OLD_THRESHOLD` / `E_ROOT_NEW_THRESHOLD`（重叠映射到后者，详情给出两侧持有人）。

一个更新包可以连续跨多个合法根中间版本（`v1→v2→v3`），每一步都独立做上述验证。

---

## 5. 通道快照与目标清单

`snapshot` 锁定**确切的目标清单摘要**：

```json
{
  "doc_type": "snapshot", "channel": "stable", "version": 1,
  "previous_version": 0, "previous_digest": "000...0",
  "root_version": 3,
  "entries": [
    {"target_id": "svc-a", "version": 1, "purpose": "runtime", "repo_tag": "core",
     "path": "app/services/svc-a.bin",
     "manifest_digest": "<目标载荷摘要>", "file_digest": "<载荷文件 sha256>"}
  ],
  "signatures": [...]
}
```

`target` 除被自身角色签名外，还必须在**同一套已确认根**下被快照覆盖：

| 检查 | 失败码 |
|---|---|
| 目标在快照 `entries` 中出现 | `E_TARGET_NOT_IN_SNAPSHOT` |
| `entry.manifest_digest == 目标载荷摘要` | `E_TARGET_NOT_CONFIRMED_ROOT` | 目标声明的 `root_version` 与已确认根不同 |
| `E_TARGET_MIXED_SNAPSHOT` |
| `entry.version == 目标 version` | `E_TARGET_NOT_CONFIRMED_ROOT` | 目标声明的 `root_version` 与已确认根不同 |
| `E_TARGET_MIXED_SNAPSHOT` |
| `entry.purpose == 目标 purpose` | `E_TARGET_PURPOSE` |
| `entry.path == 目标 path` | `E_TARGET_PATH_MISMATCH` |
| `entry.file_digest == 目标 file.digest` | `E_TARGET_DIGEST_MISMATCH` |
| `entry.repo_tag == 目标 repo_tag` | `E_TARGET_NOT_CONFIRMED_ROOT` | 目标声明的 `root_version` 与已确认根不同 |
| `E_TARGET_MIXED_SNAPSHOT` |
| `目标.channel == 快照.channel` | `E_TARGET_CHANNEL` |
| 目标引用的快照在本次包内或已确认为当前通道版本 | `E_TARGET_NOT_CONFIRMED_ROOT` | 目标声明的 `root_version` 与已确认根不同 |
| `E_TARGET_MIXED_SNAPSHOT` |
| 快照 `root_version == 已确认根版本` | `E_SNAPSHOT_NOT_CONFIRMED_ROOT` |

「符合个别签名却来自互不匹配快照的混合内容」被逐项拦截：签名可以全对，
但快照锁定的是另一份清单/路径/文件时，整包拒绝。

---

## 6. 防回退与时间规则

每个租户固定：

- 已见**根版本**；
- 每个通道的**快照版本**；
- 每个目标的**版本下限**；
- **非递减可信时间**（`trusted_time` 只能前进）。

拒绝规则：

- 包内根版本低于已确认根版本 → `E_ROOT_ROLLBACK`；
- 根版本跳跃 → `E_ROOT_VERSION_SKIP`；版本号与 `previous_version` 不一致 → `E_ROOT_VERSION_ORDER`；
- 包对已确认版本给出**不同字节** → `E_ROOT_ANCHOR_MISMATCH`；
- 快照/目标版本低于水位 → `E_SNAPSHOT_VERSION_ROLLBACK` / `E_MANIFEST_VERSION_ROLLBACK`；
- 同版本换内容 → `E_SNAPSHOT_CONFLICT` / `E_MANIFEST_CONFLICT`；
- 目标必须逐版递增且 `previous_digest` 等于上一版载荷摘要 → `E_MANIFEST_VERSION_ROLLBACK`；
- `trusted_time` 小于已存水位 → `E_TIME_ROLLBACK`。

每次发布都会先校验**已确认根本身**在当前可信时间内仍有效（`E_ROOT_EXPIRED` / `E_ROOT_NOT_YET_VALID`），
否则一个过期锚点会无限期为新快照背书。同样，目标的 `root_version` 必须等于已确认根版本
（`E_TARGET_NOT_CONFIRMED_ROOT`），不能靠快照条目「借道」其它根。

**时间窗口是半开区间 `[issued_at, expires_at)`**：`trusted_time == expires_at` 即视为过期
（`E_*_EXPIRED`），`trusted_time == expires_at - 1` 仍有效。这是独立预期场景
（`tests/test_pipeline.py::test_expiry_is_exclusive` 与 `test_valid_one_tick_before_expiry`）。

**允许上游以更高版本重新发布已知旧内容**，只要本次带**新签名**：目标版本递增、
`previous_digest` 指向上版、载荷文件字节可以与旧版相同——版本下限与签名新鲜度
（一次性 nonce，全局唯一且落库）共同保证这一点。对应 `cases.json` 第 07 条。

任何一步无效 → **整包拒绝**，不写入任何一行。

---

## 7. 模拟签名

签名覆盖的字节：

```
b"SIMUPD|v1|" + doc_type + b"|" + tenant + b"|" + payload_digest + b"|" + nonce
```

- `payload_digest` = 文档去掉 `signatures` 成员后的规范 JSON 摘要；
- `nonce` 一次性：参与过任何被接受法定人数的记录会写入 `signature_claims`，
  主键 `(tenant, key_id, gen, nonce)` 使**签名重放**成为硬失败 `E_SIGNATURE_REPLAY`；
- 验签只用调用方给定的 keyring，绝不采信文档内材料。

因此：

| 篡改方式 | 结果 |
|---|---|
| 改正文、签名未换 | `E_SIGNATURE_BAD_DIGEST` |
| 换密钥但 key 不在已确认根 | `E_SIGNATURE_INVALID` |
| 用别的角色的密钥签名 | `E_SIGNATURE_ROLE_UNAUTHORIZED` |
| 同一记录重放 | 计为重复；跨包重放 → `E_SIGNATURE_REPLAY` |

---

## 8. 两阶段：事务外验证 + 事务内重验

`Updater.prepare`（事务外）完成全部信任代数，并记录一份 `PreState`：
根版本/摘要、受影响通道版本、目标下限、可信时间。`Updater.publish` 在
`BEGIN IMMEDIATE` 内**重新推导每一条它即将提交的事实**：

1. 已确认根的版本与摘要未变；
2. 每个通道水位、每个目标下限未变；
3. 可信时间水位未被动过；
4. 磁盘上每个输入（`index.json`、每份文档、每个载荷文件）的摘要与准备时一致；
5. 所有时效窗口在本次 `trusted_time` 下仍成立；
6. 准备消费的每条签名记录尚未被消费。

全部一致才写入。写入是在**同一个事务**里完成：根行 → 快照行 → blob → 目标 →
通道指针 → 租户水位 → 签名占用 → 回执，最后提交。任一并发写者先行，后到者得到
确定性的 `E_CONCURRENCY_CONFLICT`，不会产生丢失更新，也不会发布陈旧指针。

### 8.1 数据库层的不变量（触发器强制，不依赖代码自觉）

- `roots` / `snapshots` / `target_history` / `blobs` / `signature_claims` 只可追加，任何
  `UPDATE` 直接被 `RAISE(ABORT)` 拒绝；
- `channels` 指针只能指向**已存在且摘要一致**的 `snapshots` 行；
- `targets` / `target_history` 只能指向**已存储且大小一致**的 `blobs` 行。

因此「客户端发布指针只指向已经验证且内容不可变的快照」由数据库自身保证。

### 8.2 固定版本只读查询

`Store.read_channel` / `read_target` / `read_root` 各自打开**独立的 `mode=ro` 连接**并
`PRAGMA query_only=ON`，所以：旧快照在后续提交后仍可按版本读回且内容不变；
读连接不阻塞写者，也绝不可能修改状态。

---

## 9. 崩溃同步点（可终止自己的测试进程）

| 同步点 | 位置 | 语义 |
|---|---|---|
| `before_publish_commit` | 全部行已写、回执已写、`COMMIT` 之前 | 事务未提交 → 重启后**无任何痕迹** |
| `after_commit_before_return` | `COMMIT` 成功、调用方尚未拿到返回值 | 事务已提交 → 重启后状态完整 |

触发方式：

```bash
SIMUPD_SYNC_POINT=before_publish_commit python your_worker.py
SIMUPD_SYNC_POINT_ACTION=raise      # 改为抛出 SyncPointAbort 而非 os._exit(97)
```

默认动作用 `os._exit(97)`：不跑 `atexit`、不刷新缓冲区、不执行 `COMMIT`。
`tests/test_concurrency.py::CrashFenceTests` 在**子进程**里真实触发这两个点，然后
在父进程重新打开同一个数据库，核对：

- 防回退水位没有下降（`root_version`、`channel_versions`、`target_floors`、`trusted_time`）；
- 固定版本只读视图仍返回旧快照的原字节；
- 请求重放：`after_commit_before_return` 崩溃后重放同一请求返回
  `status="replayed"` 与同一 `receipt_digest`，而不是二次提交。

---

## 10. `cases.json` 与 `result.json`

`cases.json` 是**可重放的配方**，不是输出的录制：它保存租户布局、密钥材料、要合成的
文档与要执行的步骤，重放时从零重建每个包（逐字节确定）。

用例形态：

```json
{
  "format": "simupd-cases/1",
  "cases": [{
    "name": "01-happy-two-rotations",
    "tenant": {"tenant": "acme-updates", "holders": {...}},
    "bootstrap": {"chain": [...], "root": {...}, "trusted_time": 1000},
    "steps": [
      {"kind": "update", "build": {...}, "trusted_time": 1300, "request_id": "req-01",
       "expect": {"status": "committed", "root_version": 3}},
      {"kind": "query", "query": {"kind": "audit"}, "expect": {"ok": true, "root_version": 3}}
    ]
  }]
}
```

文档合成支持两段式篡改，用来精确制造负例：

- `tamper_before_sign`：**先改正文再签名** → 签名正确但内容有错；
- `tamper_after_sign`：**签名后再改正文** → 内容对但签名失配。

包级突变通过 `mutations` 表达：`omit_from_mirror`（镜像缺文件）、
`mirror_override`（两镜像内容不同）、`non_canonical_document`（非规范 JSON 字节）。

`result.json`：

```json
{
  "format": "simupd-results/1",
  "cases": [
    {"case": "01-happy-two-rotations", "ok": true, "failure": null,
     "steps": [{"step": "bootstrap", "ok": true, "actual": {...}, "problems": []},
               {"step": 1, "ok": true, "actual": {...}, "problems": []}]}
  ],
  "summary": {"total": 10, "passed": 10, "failed": 0}
}
```

更新的 `actual` 含 `status`、`root_version`、`root_digest`、`root_steps`、`channels`、
`targets`、`receipt_digest`、`package_digest`，以及**信任验证表** `trust_table`。
拒绝时 `actual` 为 `{"status": "rejected", "error_code": ..., "error_message": ..., "error_detail": ...}`。

---

## 11. 错误码

| 码 | 触发条件 |
|---|---|
| `E_INPUT_INVALID` | 输入不是合法 JSON / 字段类型错误 / 文档非规范编码 / 租户不符 |
| `E_UNKNOWN_TENANT` | 租户没有信任锚 |
| `E_PATH_ESCAPE` | 路径越界、绝对路径、含 `..`、段含非法字符 |
| `E_FILE_MISSING` | 包内没有被签名的载荷文件 |
| `E_FILE_DIGEST_MISMATCH` | 载荷文件摘要或大小与签名清单不符 |
| `E_MIRROR_MISSING` | 某镜像缺文件或镜像目录不存在 |
| `E_MIRROR_DIVERGENCE` | 两镜像字节不一致 |
| `E_ROOT_DOC_INVALID` | 根文档结构非法（版本链、时间窗、角色、keyring、阈值 > 持有人数） |
| `E_ROLE_EXCLUSIVITY` | 持有人或密钥跨角色复用 |
| `E_ROOT_VERSION_ORDER` | 新根/快照未链接到上一版摘要 |
| `E_ROOT_VERSION_SKIP` | 根版本跳跃 |
| `E_ROOT_ROLLBACK` | 根版本低于已确认版本 |
| `E_ROOT_ANCHOR_MISMATCH` | 已确认版本被替换成不同字节 |
| `E_ROOT_EXPIRED` / `E_ROOT_NOT_YET_VALID` | 根超出 `[issued_at, expires_at)` |
| `E_ROOT_OLD_THRESHOLD` | 旧根 root 角色未达阈值 |
| `E_ROOT_NEW_THRESHOLD` | 新根 root 角色未达阈值，或两套法庭无法由互斥持有人满足 |
| `E_ROOT_HOLDER_OVERLAP` | 沿用的 key id 密钥材料发生变化 |
| `E_SNAPSHOT_INVALID` | 快照结构非法 |
| `E_SNAPSHOT_VERSION_ROLLBACK` | 快照版本低于通道水位，或版本跳跃 |
| `E_SNAPSHOT_VERSION_ORDER` | 快照未链接到通道上一版摘要 |
| `E_SNAPSHOT_CONFLICT` | 同通道同版本换内容 |
| `E_SNAPSHOT_EXPIRED` / `E_SNAPSHOT_NOT_YET_VALID` | 快照超出时间窗（含恰好到期） |
| `E_SNAPSHOT_THRESHOLD` | 快照角色未达阈值 |
| `E_SNAPSHOT_UNAUTHORIZED` | 快照角色的标签或路径授权不覆盖其条目 |
| `E_SNAPSHOT_NOT_CONFIRMED_ROOT` | 快照/目标不属于已确认根 |
| `E_MANIFEST_INVALID` | 目标结构非法 |
| `E_MANIFEST_VERSION_ROLLBACK` | 目标版本低于下限、跳版、或 `previous_digest` 不匹配 |
| `E_MANIFEST_CONFLICT` | 同目标同版本换内容 |
| `E_TARGET_NOT_CONFIRMED_ROOT` | 目标声明的 `root_version` 与已确认根不同 |
| `E_TARGET_MIXED_SNAPSHOT` | 目标与快照锁定的清单/版本/标签不匹配，或快照不可确认 |
| `E_TARGET_NOT_IN_SNAPSHOT` | 快照未列出该目标 |
| `E_TARGET_DIGEST_MISMATCH` | 目标文件摘要与快照条目不符 |
| `E_TARGET_PURPOSE` / `E_TARGET_PATH_MISMATCH` / `E_TARGET_CHANNEL` | 用途/路径/通道与快照条目不符 |
| `E_TARGET_UNAUTHORIZED` / `E_TARGET_PATH_UNAUTHORIZED` | 目标角色的标签 / 路径授权不覆盖 |
| `E_TARGET_THRESHOLD` | 目标角色未达阈值 |
| `E_TARGET_EXPIRED` / `E_TARGET_NOT_YET_VALID` | 目标超出时间窗（含恰好到期） |
| `E_SIGNATURE_INVALID` | 结构非法、密钥未知、HMAC 不匹配 |
| `E_SIGNATURE_BAD_DIGEST` | 签名绑定的是另一份文档摘要 |
| `E_SIGNATURE_ROLE_UNAUTHORIZED` | 用其它角色的密钥签名 |
| `E_SIGNATURE_REPLAY` | 签名记录已被消费 |
| `E_TIME_ROLLBACK` | 可信时间倒退 |
| `E_ROLLBACK_DETECTED` | 状态审计发现水位或指针/blob 不一致 |
| `E_CONCURRENCY_CONFLICT` | 事务内重验发现状态或输入在准备后发生变化 |
| `E_STORE_BUSY` | SQLite 写锁不可获得 / 提交失败 |
| `E_REQUEST_REPLAY_CONFLICT` | 同一 `request_id` 用于不同更新包 |
| `E_SYNC_POINT_ABORTED` | 同步点以 `raise` 动作触发（仅测试） |

---

## 12. 跨两次根轮换的完整正例

根链：`v1 {alice,bob,carol} → v2 {carol,dave,alice} → v3 {alice,dave,bob}`。
每一步旧、新阈值均为 2，且两套法庭互斥：

- `v1→v2`：旧 `{alice,bob}`，新 `{carol,dave}`；
- `v2→v3`：旧 `{carol,dave}`，新 `{alice,bob}`。

一个包同时完成两次轮换，并在 `root v3` 下发布通道 `stable` v1（快照 `{eve,frank}`）与两个
目标 `svc-a`、`lib-c`（目标角色 `{heidi,ivan}`）。

`python tools/trust_table.py` 的实测输出：

```
### Cross-rotation positive example

Status: **committed**, root v1 -> v3, 2 rotation step(s).

### Independent trust verification table

| # | Document | Version | Quorum | Holders | Digests / links | Verdict |
|---|----------|---------|--------|---------|-----------------|---------|
| 1 | root rotation | 1 -> 2 | old 2 / new 2 | alice, bob / carol, dave | link=True, disjoint=True, roles-exclusive=True | ACCEPT |
| 2 | root rotation | 2 -> 3 | old 2 / new 2 | alice, carol / bob, dave | link=True, disjoint=True, roles-exclusive=True | ACCEPT |
| 3 | snapshot stable | 1 | 2 | eve, frank | root-under-v3, authorized=True | ACCEPT |
| 4 | target svc-a | 1 | 2 | heidi, ivan | manifest-locked=True, file-locked=True, authorized=True | ACCEPT |
| 4 | target lib-c | 1 | 2 | heidi, ivan | manifest-locked=True, file-locked=True, authorized=True | ACCEPT |

Independent verdict: **ALL ACCEPT**
```

这张表**独立于客户端回执**：它直接对磁盘上的文档重新做签名计数、阈值判定、角色授权
与摘要比对，不复用 `Updater` 的结论。

---

## 13. 实测结果

在 Windows 11 + Python 3.12.8（`sqlite3` 3.45.3）下：

```text
$ python -m solution --input cases.json --output result.json
10/10 cases matched (0 failed) -> result.json

$ python -m unittest discover -s tests -v
Ran 72 tests in 9.5s
OK
```

`cases.json` 的 10 个用例：

| # | 用例 | 预期 |
|---|---|---|
| 01 | `01-happy-two-rotations` | `committed`，`v1→v3`，2 次轮换，1 快照 2 目标 |
| 02 | `02-reject-root-rollback` | `E_ROOT_ROLLBACK` |
| 03 | `03-reject-old-root-quorum-missing` | `E_ROOT_OLD_THRESHOLD` |
| 04 | `04-reject-shared-holder-fills-both-seats` | `E_ROOT_NEW_THRESHOLD` |
| 05 | `05-reject-duplicate-key-one-seat` | `E_TARGET_THRESHOLD`（同一持有人两把密钥仍一席） |
| 06 | `06-reject-target-version-floor` | `E_MANIFEST_VERSION_ROLLBACK` |
| 07 | `07-allow-republished-old-content-new-signature` | `committed`，旧字节以 v2 重新发布 |
| 08 | `08-reject-mixed-snapshot-target` | `E_TARGET_PATH_MISMATCH` |
| 09 | `09-reject-expired-exact` | `E_SNAPSHOT_EXPIRED`（恰好到期） |
| 10 | `10-reject-root-role-duplicate-signer` | `E_ROOT_OLD_THRESHOLD`（重复签名只占一席） |

重放两次 `result.json` 逐字节相同（`tests/test_cases_replay.py::test_replay_is_deterministic`）。

测试套件（72 项）覆盖：

- `test_trust_algebra.py`：阈值按席位、重复签名、吊销代数、跨角色密钥、未知密钥、
  篡改正文、轮换 Hall 可行性、角色互斥、整段前缀匹配；
- `test_pipeline.py`：正例、根回滚/跳版、快照根归属、时间倒退、路径越权、
  文件摘要不符/缺失、精确到期与到期前一瞬、非规范 JSON、镜像缺失/分歧、路径越界；
- `test_concurrency.py`：两写者一胜一冲突、另一写者先行换根、请求重放与冲突、
  6 线程竞争恰好一胜、固定版本只读视图、读连接只读、数据库拒绝改写已发布行、
  指针不能悬空；以及**子进程在两个同步点被杀**后的重启核对；
- `test_cases_replay.py`：`cases.json` 结构、全绿重放、确定性、CLI 退出码 0/1/2、
  README 声明的调用串确实存在。

---

## 14. 目录结构

```
solution/
  __main__.py     # CLI：--input / --output，退出码 0/1/2
  cases.py        # cases.json 解释器：合成 → 准备 → 发布 → 结果
  updater.py      # prepare（事务外）/ publish（事务内重验 + 原子提交）
  docs.py         # 文档结构、角色策略代数、阈值与轮换 Hall 判定
  signing.py      # 模拟签名（HMAC-SHA256 + nonce）
  canonical.py    # 规范 JSON、摘要、仓库路径规则
  loader.py       # 双镜像加载与逐字节比对
  builder.py      # 确定性文档/包合成
  state.py        # SQLite schema、触发器、原子发布、只读视图、审计
  syncpoint.py    # 崩溃同步点
  errors.py       # 错误码
tests/            # 72 个断言具体结果的测试
tools/            # cases.json 生成器、信任验证表
cases.json        # 10 个可重放用例
result.json       # 最近一次 10/10 的实测输出
```
