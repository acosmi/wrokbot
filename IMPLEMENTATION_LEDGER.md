# Wrok Bot 后端实施台账

更新时间：2026-09-19。实施人：grokbot。GitHub任务实施人：wrok code。

本台账记录实施与验证事实，不定义产品能力或架构。每个任务对应一个独立 PR，按编号顺序集成。PR 链接中的合并状态与提交是远端集成事实；局部测试通过不表示产品阶段或发布验收完成。

## 任务与 PR

001–044 的合并状态与提交已从 GitHub 重新核对；这些任务的历史运行结论本轮未全部重测。

| 任务 | 交付范围 | 状态 | PR | 合并提交 |
|---|---|---|---|---|
| V6-PR-001 | 启动owner与初始化拒绝边界 | 已合入 | [#8](https://github.com/acosmi/wrokbot/pull/8) | [61e783b9a4](https://github.com/acosmi/wrokbot/commit/61e783b9a400a0a2c947e6767ea6700c8fc43a21) |
| V6-PR-002 | SCRAM持久意图 | 已合入 | [#9](https://github.com/acosmi/wrokbot/pull/9) | [3eacd5600e](https://github.com/acosmi/wrokbot/commit/3eacd5600e018ed49168194a1fd49e4acba64df9) |
| V6-PR-003 | 验收记录集合与候选检查 | 已合入 | [#10](https://github.com/acosmi/wrokbot/pull/10) | [cfb044ef25](https://github.com/acosmi/wrokbot/commit/cfb044ef259b9f09ec8a7fb084206a19b72daa1b) |
| V6-PR-004 | 主密钥日志与PG canary | 已合入 | [#11](https://github.com/acosmi/wrokbot/pull/11) | [8cfe1bc0fc](https://github.com/acosmi/wrokbot/commit/8cfe1bc0fc14a816b89ebb6b6c855a5960ab6692) |
| V6-PR-005 | 启动诊断错误投影 | 已合入 | [#12](https://github.com/acosmi/wrokbot/pull/12) | [ffc7e08a00](https://github.com/acosmi/wrokbot/commit/ffc7e08a00ece74e8505e85d5c222dc72ded9627) |
| V6-PR-006 | 工具装配守卫 | 已合入 | [#13](https://github.com/acosmi/wrokbot/pull/13) | [3fdcef6de0](https://github.com/acosmi/wrokbot/commit/3fdcef6de02091d87ecd3b489e7a53220923ed7e) |
| V6-PR-007 | 数据面错误传递 | 已合入 | [#14](https://github.com/acosmi/wrokbot/pull/14) | [a537b4da32](https://github.com/acosmi/wrokbot/commit/a537b4da32bfbc53de49f8a035ae2c59a01cc4e5) |
| V6-PR-008 | macOS进程身份观察 | 已合入 | [#15](https://github.com/acosmi/wrokbot/pull/15) | [78786d8c30](https://github.com/acosmi/wrokbot/commit/78786d8c308888bfed3d81fa0e5d5bd1eede413e) |
| V6-PR-009 | PG启动journal | 已合入 | [#16](https://github.com/acosmi/wrokbot/pull/16) | [963e44010f](https://github.com/acosmi/wrokbot/commit/963e44010f0a0076d0f2ba9670c00bdd8f877777) |
| V6-PR-010 | 辅助进程journal | 已合入 | [#17](https://github.com/acosmi/wrokbot/pull/17) | [5964c9b64b](https://github.com/acosmi/wrokbot/commit/5964c9b64be098a089e637916c55c90fac339342) |
| V6-PR-011 | 数据目录打开者观察 | 已合入 | [#18](https://github.com/acosmi/wrokbot/pull/18) | [e2c1a04f6c](https://github.com/acosmi/wrokbot/commit/e2c1a04f6cb6458a8cbd306226924031df7cb7fa) |
| V6-PR-012 | 静止实例与启动锁回收 | 已合入 | [#19](https://github.com/acosmi/wrokbot/pull/19) | [f21d00d103](https://github.com/acosmi/wrokbot/commit/f21d00d1033d847911559d9d280efbd6a8766705) |
| V6-PR-013 | 中间态journal恢复 | 已合入 | [#20](https://github.com/acosmi/wrokbot/pull/20) | [f3355c8981](https://github.com/acosmi/wrokbot/commit/f3355c89819bbab80000ebf13558bab3d0cdb81c) |
| V6-PR-014 | 恢复epoch | 已合入 | [#21](https://github.com/acosmi/wrokbot/pull/21) | [72910c3900](https://github.com/acosmi/wrokbot/commit/72910c3900c8ec0c4f1fce5416e8c0a369fb271e) |
| V6-PR-015 | 辅助journal终态收口 | 已合入 | [#22](https://github.com/acosmi/wrokbot/pull/22) | [2a82d580da](https://github.com/acosmi/wrokbot/commit/2a82d580da5d53590ae74ed1d785811e72929b5d) |
| V6-PR-016 | 未消费epoch秘密写入门 | 已合入 | [#23](https://github.com/acosmi/wrokbot/pull/23) | [8d91bdbba2](https://github.com/acosmi/wrokbot/commit/8d91bdbba2480fc5c2bf96e0b2237a2fdf9e42ed) |
| V6-PR-017 | Existing消费恢复epoch | 已合入 | [#24](https://github.com/acosmi/wrokbot/pull/24) | [378cd756bd](https://github.com/acosmi/wrokbot/commit/378cd756bd1d928ae306f9cb795c657f8b67cfa6) |
| V6-PR-018 | Fresh消费恢复epoch | 已合入 | [#25](https://github.com/acosmi/wrokbot/pull/25) | [207e14105e](https://github.com/acosmi/wrokbot/commit/207e14105e3fe20625a6a8b10b2f250696ba6aef) |
| V6-PR-019 | 授权失效required记录 | 已合入 | [#26](https://github.com/acosmi/wrokbot/pull/26) | [378f301b36](https://github.com/acosmi/wrokbot/commit/378f301b367a82bdaa7132a9652ba44a19725a69) |
| V6-PR-020 | 推进授权代次 | 已合入 | [#27](https://github.com/acosmi/wrokbot/pull/27) | [74fc479529](https://github.com/acosmi/wrokbot/commit/74fc4795292bc807f05443b4f2cd791ac1a5d1cf) |
| V6-PR-021 | 终止旧本机会话 | 已合入 | [#28](https://github.com/acosmi/wrokbot/pull/28) | [c89e9b7091](https://github.com/acosmi/wrokbot/commit/c89e9b7091cdf83daf86b208b440035cf6dfb9dc) |
| V6-PR-022 | 陈旧postmaster记录验证 | 已合入 | [#29](https://github.com/acosmi/wrokbot/pull/29) | [676b7ca21b](https://github.com/acosmi/wrokbot/commit/676b7ca21b52a16109ca9b525c2c0b2dbfb17c92) |
| V6-PR-023 | 取消待定工具审批 | 已合入 | [#30](https://github.com/acosmi/wrokbot/pull/30) | [0dc9b1a308](https://github.com/acosmi/wrokbot/commit/0dc9b1a308abc2f541beafce6b97b667e964d212) |
| V6-PR-024 | 授权失效幂等见证 | 已合入 | [#31](https://github.com/acosmi/wrokbot/pull/31) | [03d8bf5f13](https://github.com/acosmi/wrokbot/commit/03d8bf5f13f2278e0d732dc7aecbb62f1b3e04de) |
| V6-PR-025 | 审批取消同事务审计 | 已合入 | [#32](https://github.com/acosmi/wrokbot/pull/32) | [af74f2eced](https://github.com/acosmi/wrokbot/commit/af74f2eced7fb05c4b8e347d54a8767dba5f49a6) |
| V6-PR-026 | 真实PG授权推进矩阵 | 已合入 | [#33](https://github.com/acosmi/wrokbot/pull/33) | [9ef02bb057](https://github.com/acosmi/wrokbot/commit/9ef02bb057ba95fb27f94fa6d3372efda804cfb8) |
| V6-PR-027 | 过期成员线程租约 | 已合入 | [#34](https://github.com/acosmi/wrokbot/pull/34) | [c678c3486a](https://github.com/acosmi/wrokbot/commit/c678c3486a75290e818571feea5dbaa69190a7b1) |
| V6-PR-028 | 中止已铸造执行能力 | 已合入 | [#35](https://github.com/acosmi/wrokbot/pull/35) | [02da9c61c2](https://github.com/acosmi/wrokbot/commit/02da9c61c22ea9e23a88494b9754bc500afb6700) |
| V6-PR-029 | 取消待定人工决策 | 已合入 | [#36](https://github.com/acosmi/wrokbot/pull/36) | [757f6be9ad](https://github.com/acosmi/wrokbot/commit/757f6be9adf4daf55bf619b489cf4bcabb187e71) |
| V6-PR-030 | 过期远程人工中断 | 已合入 | [#37](https://github.com/acosmi/wrokbot/pull/37) | [08e230ebe2](https://github.com/acosmi/wrokbot/commit/08e230ebe20b00f4e28aa11006018427d9864688) |
| V6-PR-031 | 异常退出后Existing恢复 | 已合入 | [#38](https://github.com/acosmi/wrokbot/pull/38) | [0e5655f440](https://github.com/acosmi/wrokbot/commit/0e5655f4400825ad1e3229549bba24113b2d2e85) |
| V6-PR-032 | 两个恢复者唯一writer | 已合入 | [#39](https://github.com/acosmi/wrokbot/pull/39) | [835201a8cc](https://github.com/acosmi/wrokbot/commit/835201a8cc9b29ef3d2996b53b753112bad1073e) |
| V6-PR-033 | 父进程退出但子进程存活时拒绝 | 已合入 | [#40](https://github.com/acosmi/wrokbot/pull/40) | [ab6e7457fd](https://github.com/acosmi/wrokbot/commit/ab6e7457fd5bbf5e4905c27e2aaed58c4109ce0b) |
| V6-PR-034 | 截断启动锁拒绝 | 已合入 | [#41](https://github.com/acosmi/wrokbot/pull/41) | [1a6204268b](https://github.com/acosmi/wrokbot/commit/1a6204268bb3d9515744153e2f2c642aca75134e) |
| V6-PR-035 | PID复用身份不等价 | 已合入 | [#42](https://github.com/acosmi/wrokbot/pull/42) | [d3c8bb13b7](https://github.com/acosmi/wrokbot/commit/d3c8bb13b74a3bfd644ff810ef4ee0377e2fb584) |
| V6-PR-036 | 恢复中再次退出后持久重验 | 已合入 | [#43](https://github.com/acosmi/wrokbot/pull/43) | [116c90bd74](https://github.com/acosmi/wrokbot/commit/116c90bd74e06757d342ea2b87230f56a6577be0) |
| V6-PR-037 | 恢复元数据AEAD包装 | 已合入 | [#44](https://github.com/acosmi/wrokbot/pull/44) | [2185a7d142](https://github.com/acosmi/wrokbot/commit/2185a7d1424b650d039f2589598783b1b0829d1c) |
| V6-PR-038 | 分块序号和清单AAD绑定 | 已合入 | [#45](https://github.com/acosmi/wrokbot/pull/45) | [139b7592eb](https://github.com/acosmi/wrokbot/commit/139b7592eb2f61cbc827578d5fb0b741b3b734d9) |
| V6-PR-039 | 归档容器有界读写 | 已合入 | [#46](https://github.com/acosmi/wrokbot/pull/46) | [2e52377e25](https://github.com/acosmi/wrokbot/commit/2e52377e256893c0ffec9c3d9f2e841d212152c0) |
| V6-PR-040 | 完整认证归档解包；公开执行台账精确白名单 | 已合入 | [#47](https://github.com/acosmi/wrokbot/pull/47) | [31e5c364f2](https://github.com/acosmi/wrokbot/commit/31e5c364f2c56976304b63f522f8ab92574730f6) |
| V6-PR-041 | 归档写出分配前预算与配置硬上限 | 已合入 | [#48](https://github.com/acosmi/wrokbot/pull/48) | [eb75f8b47a](https://github.com/acosmi/wrokbot/commit/eb75f8b47a33474c61bb1510440c924ae0d00d8c) |
| V6-PR-042 | 最大合法恢复信封自读回 | 已合入 | [#49](https://github.com/acosmi/wrokbot/pull/49) | [45d69618f3](https://github.com/acosmi/wrokbot/commit/45d69618f39e5ddd049d60b60eb0fae62146896a) |
| V6-PR-043 | 已知数据库版本门与原 canary 重核 | 已合入 | [#50](https://github.com/acosmi/wrokbot/pull/50) | [78354b95df](https://github.com/acosmi/wrokbot/commit/78354b95df78adb897abf72c9528a8d9f92113e2) |
| V6-PR-044 | SDK 5.0 正式制品、许可与宿主传输接纳 | 已合入 | [#51](https://github.com/acosmi/wrokbot/pull/51) | [0af43c89d1](https://github.com/acosmi/wrokbot/commit/0af43c89d1c0fb39cb07be35a8bbc660b97311b9) |
| V6-PR-045 | 固定网关账户身份读取与有界宿主传输 | 主控验收通过，待独立 PR | 待创建 | 尚未合入 |
| V6-PR-046 | 自定义模型选择的四入口与队列消费 | 实施中，尚未验收 | 待创建 | 尚未合入 |

## macOS 首发进度

当前尚无 A0–A7 中任何一项取得完整同候选通过证据；局部 PR 数量不代表首发完成比例。持续实施到首发验收完成。

| 部分 | 当前事实 |
|---|---|
| 启动与数据保护 | 多个真实 PG 子场景已验；完整签名 App 旅程仍待验 |
| 三模型 | custom 后端已有链路；SDK5 已接纳并通过宿主传输验证、生产PG/Vault与连接仍待接；账户桥更新已核源、Rust适配待做 |
| Browser / 原生 | 有协调核心；实际执行、画面与GUI完整装配仍有缺口 |
| 备份恢复 | 加密/归档基础已验；PG恢复、切换及完整演练未完成 |
| 签名与交付 | 本机存在有效Developer ID身份；实际候选签名、公证及发行图验收待完成 |

## 本批验证

040 主控已亲读实现与测试，并在同一候选运行：

- `cargo test -p openbot-infra --offline --locked --lib -- backup::archive_bundle`：22 通过，包括 13 项解包测试和 9 项容器回归。
- `cargo test -p openbot-domain --offline --locked --lib -- backup::recovery_`：9 通过。
- `python3 -m unittest tools.test_repository_guard`：8 通过。
- `cargo check -p openbot-infra --offline --locked --no-default-features --features desktop-local-vault --lib`：通过。

认证后的总长度不符、有效前缀后的外包末块、损坏和乱序均无成功结果。未执行 PostgreSQL 恢复或实际 OS 验收。

041 主控已亲读实现与独立预期字节测试，归档链 29 项通过（7 项写出边界、13 项解包、9 项容器回归），Desktop Local infra 的 offline/locked 构建通过。写出字段顺序与原格式一致，超预算时输出 writer 的 write/flush 调用数均为零；实际 I/O 失败仍可保留已写前缀。

042 主控已验证 domain 恢复 13 项、归档链 30 项以及 Desktop Local infra 构建通过。独立探针用相同 4096 字节输入确认信封为 8334 字节，解析结果由失败变为成功；最大合法数据经归档写读和认证解包恢复原字节。

043 主控亲读六个源码/测试文件，使用独立 PostgreSQL 17.11 验证：已知账本前缀拒绝矩阵、0032形态回归、Desktop bootstrap错误master/canary改删/跨库proof矩阵、实际sidecar→Vault→Application组合，四个定向测试均通过；Desktop Launcher all-target offline/locked check通过。当前32无重复迁移；真实32→下一新schema的升级矩阵随首次新migration另验。

044 主控核定 exact SDK5 制品/源码/LICENSE，Cargo.lock仅SDK版本/checksum变化；三个依赖许可原文及SPDX关系核同，原59条来源保留、总62条。18项真实TLS测试、六目标依赖图、四组Server/SSO/Desktop feature并集、Launcher all-target check均通过，SDK自带HTTP/TLS/WS和UI依赖边均未启用。初始测试模块路径和HTTP EOF预期错误已修正留证；SDK `[DONE]`后的body Drop保留Cancelled事实，不伪报HTTP EOF或用户取消。

045 主控亲读九个源码/测试/守卫文件；真实 TLS 测试 24 项通过（原 18 项与新 6 项），依赖边界检查及 Desktop Launcher all-target offline/locked check 通过。验证显式开放的账户端点、固定身份协议、无效请求在发送前拒绝、身份一致性、脱敏、取消、零重定向及 64 KiB 路由预算。结果仅为协议读取能力，未证明真实账户登录、凭据持久化或完整三模型旅程。

## 仍未完成

- 归档容器容量仍是单独预算，不能将 4 MiB 理论明文上限当作外层 8 MiB 容器的可承载保证。
- PostgreSQL/WAL 恢复、隔离暂存的产品装配、同机与新安装恢复演练、签名升级及 A6。
- 旧 0031 数据的合法恢复输入；不能推测旧密文或凭据。
- 稳定签名、真实 OS 权限与旧 Keychain 访问验证。
- SDK 的 PG/Vault 当前授权、三种模型完整旅程；账户桥更新来源已核定，Rust 接入与真实厂商旅程仍待完成。
- Browser 与原生电脑的完整产品链、A0–A7 同一候选验收和 24 小时 soak。
- M1 事件与同节点协作、M2 节点与文件能力，以及完整平台、安全和发布验收。

040 只验证有界归档的认证消费，不授予恢复切换权限，不关闭以上工作。
