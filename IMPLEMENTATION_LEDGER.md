# Wrok Bot 后端实施台账

更新时间：2026-09-30。独立验收主控核对远端与新机状态；2026-09-19 的实施、实测记录保留为历史记录。

001–047 已合入；048–058 已有开放候选，逐项独立验收中。后端规范原件已在本机核对；旧机原始 QA 和其余缺失输入尚未恢复，不能把历史自报转记为新机验收通过。

本台账记录实施与验证事实，不定义产品能力或架构。每个任务对应一个独立 PR，按冻结合同及实际依赖顺序集成。PR 链接中的合并状态与提交是远端集成事实；局部测试通过不表示产品阶段或发布验收完成。

## 任务与 PR

001–047 的合并提交本轮均核实为 main 的祖先；047 的实际远端合并记录已核对。历史运行结论本轮未全部重测，集成事实与测试通过证据分别记录。

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
| V6-PR-045 | 固定网关账户身份读取与有界宿主传输 | 已合入 | [#52](https://github.com/acosmi/wrokbot/pull/52) | [38c7259a18](https://github.com/acosmi/wrokbot/commit/38c7259a187e719831b007202c5c4a3f5061f702) |
| V6-PR-046 | 自定义模型四入口、队列消费与 UI 目录改名 | 已合入 | [#53](https://github.com/acosmi/wrokbot/pull/53) | [c970fced2e](https://github.com/acosmi/wrokbot/commit/c970fced2eb07f950033f42c8d13795e496b3e22) |
| V6-PR-047 | SDK 个人凭据的 PG/Vault 持久授权与严格刷新 | 已合入；本轮核实祖先，历史测试未重跑 | [#54](https://github.com/acosmi/wrokbot/pull/54) | [f93ffcbe7c](https://github.com/acosmi/wrokbot/commit/f93ffcbe7c66338f4014e30366942262f777387b) |
| V6-PR-048 | 第一方技术命名统一与既有数据兼容 | 精确命名合同未冻结，候选保留待验 | [#59](https://github.com/acosmi/wrokbot/pull/59) | 未合入 |
| V6-PR-049 | archive_bundle Clippy 修复 | 主控已验且已合 | [#60](https://github.com/acosmi/wrokbot/pull/60) | [45a0c4a7ac](https://github.com/acosmi/wrokbot/commit/45a0c4a7ac826b47884cd313f6313b461cf41379) |
| V6-PR-050 | native_0027/0028 历史幂等重检 | 主控已验且已合 | [#62](https://github.com/acosmi/wrokbot/pull/62) | [1f8e24b674](https://github.com/acosmi/wrokbot/commit/1f8e24b674dcd26c2478f6c0b7e40ed80eb32e97) |
| V6-PR-051 | Infra 测试 Clippy 修复 | 主控已验，集成状态见 PR | [#64](https://github.com/acosmi/wrokbot/pull/64) | 未合入 |
| V6-PR-052 | Desktop ScreenSessionService 局部装配 | 开放候选，待独立验收 | [#67](https://github.com/acosmi/wrokbot/pull/67) | 未合入 |
| V6-PR-053 | transport_parity 的 ModelConnection 变体分类 | 开放候选，待独立验收 | [#68](https://github.com/acosmi/wrokbot/pull/68) | 未合入 |
| V6-PR-054 | skip-link 键盘焦点修复 | 开放候选，待独立验收 | [#70](https://github.com/acosmi/wrokbot/pull/70) | 未合入 |
| V6-PR-055 | UI wasm32 Clippy 修复 | 开放候选，待独立验收 | [#71](https://github.com/acosmi/wrokbot/pull/71) | 未合入 |
| V6-PR-056 | Desktop Clippy 修复 | 开放候选，待独立验收 | [#72](https://github.com/acosmi/wrokbot/pull/72) | 未合入 |
| V6-PR-057 | 既有格式差异修复 | 开放候选，待独立验收 | [#74](https://github.com/acosmi/wrokbot/pull/74) | 未合入 |
| V6-PR-058 | AG-UI fixture README provenance 修复 | 主控已验且已合 | [#76](https://github.com/acosmi/wrokbot/pull/76) | [9a3b5c7234](https://github.com/acosmi/wrokbot/commit/9a3b5c7234b8362e4765726c52a6db1c73e08a36) |
| V6-PR-059 | SDK 自有登录合同草案 | 未批准；不得据此实施 | 无生产候选 PR | 未合入 |
| V6-PR-060 | Sidecar 失败证据与受控恢复测试 | 旧候选未取回；需核冻结合同后最小重建 | 未找到对应 PR | 未重建 |
| V6-PR-061 | macOS version helper 读取中执行输出预算 | 旧候选未取回；源码仍为收集后检查 | 未找到对应 PR | 未重建 |
| V6-PR-062 | initdb 继承控制终端的口令读取路径 | 仅诊断；生产修复合同未批准 | 无生产修复 PR | 未完成 |
## macOS 首发进度

当前尚无 A0–A7 中任何一项取得完整同候选通过证据；局部 PR 数量不代表首发完成比例。持续实施到首发验收完成。

| 部分 | 当前事实 |
|---|---|
| 启动与数据保护 | 多个真实 PG 子场景已验；完整签名 App 旅程仍待验 |
| 三模型 | custom 后端与四入口UI已局部验收；SDK5及账户身份已合，PG/Vault已完成本机及组合验收，集成记录见047；登录及模型运行组合仍待，账户桥Rust适配待做 |
| Browser / 原生 | 有协调核心；实际执行、画面与GUI完整装配仍有缺口 |
| 备份恢复 | 加密/归档基础已验；PG恢复、切换及完整演练未完成 |
| 签名与交付 | 旧机曾记录有效 Developer ID 身份；本轮新机查询为 0 个有效身份，实际候选签名、公证及发行图验收待完成 |

## 历史验证（原始 QA 本轮未取回）

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

046 主控亲读目录迁移及全部内容变化，最终候选 216 项 UI 单测、9 项发布守卫、严格 Clippy、生产 WASM/release 构建、中英文 1068 键、样式与资源预算检查通过。模型四入口、FIFO、有序技能、键盘、明确冲突和 Unknown 共 13 项浏览器请求场景在队列修复候选通过；其后错误提示修复重验 5 项受影响场景，最后收件人恢复修复在最终构建重验。不同构建的证据分别保留，未冒充全部场景在最终构建重跑。创建响应丢失时不再次创建，运行结果不明时仅显式原请求重试；目录版本冲突要求重新选择。首次读回操作漏选模型的失败记录保留并按原预期重做。浏览器使用合成 HTTP/SSE 后端；实际厂商、PG组合、Wry、完整可访问性与首发 A 门仍待。CSS 为 130505/131072 字节，已超过预警线，未放宽预算。UI 依赖守卫使用 locked/offline 元数据选中的实际来源通过；默认全局缓存因重复 registry 源首次拒绝，失败保留，未修改全局缓存或依赖。

047 主控亲读 25 个产品、schema、测试和守卫文件。独立 PostgreSQL 验证：历史及新增 schema 6 项、Desktop bootstrap 3 项、Server 初始化 4 项、人员撤权恢复 1 项、自定义模型三协议 PG/TLS 1 项均通过。SDK 持久授权 12 个场景分两次完成验证（首轮 11 通过，纠正 SDK Missing 对象语义的测试预期后，剩余 1 项通过）；原 24 项 TLS、78 项数据库单测、依赖守卫和 Launcher all-target check 通过。初期编译错误和失败日志已保留；四个越界格式改动已恢复。并发刷新仅一次请求，响应丢失、取消、主体漂移及两阶段审计故障后保留未决状态，不重发旧令牌。接入已合入的 046 后，25 个后端文件及 265 个 UI/路径文件的已验内容均不变；主控补跑 Launcher all-target、SDK 依赖守卫及 9 项发布守卫通过。真实 App 登录、v2 模型运行和厂商旅程仍待。

051 历史候选 bfb79b542b02ed470cafa3bbecceccb855cf5859 的作者记录（原始 QA 本轮未取回；新增 allow 已进入返修）：

051 主控亲读 gateway_authority 三个测试文件与 gateway_sdk_transport/tls.rs，修复 issue #61 记录的第二波既有 clippy 问题（此前被 #58 的库编译失败长期遮蔽）：10 处（原报告 9 处，复核时另发现 1 处未覆盖的同构代码）`.err().expect(msg)`，其中 9 处机械改为等价的 `.expect_err(msg)`；第 10 处（`pending_failures.rs` 的 `assert_pending_without_second_post`）因 `Ok` 类型 `acosmi::Client` 有意不实现 `Debug`（避免意外泄漏存活 token）导致该改法无法编译，保留原写法并加定点 `#[allow(clippy::err_expect)]` 及理由注释。`gateway_sdk_transport/tls.rs` 的 3 处 `dead_code`（`Capture::headers`、`TlsFixture::tls_failures`、`chat_text`）根因是该文件被 `gateway_authority.rs` 与 `gateway_sdk_transport.rs` 两个测试二进制通过 `include!` 共享，字段/函数在后者的编译单元里有真实读取、在前者里没有；加 `#[allow(dead_code)]` 及理由注释，未做删除（删除会破坏真正用到它们的二进制）。验证：`cargo clippy -p openbot-infra --all-targets -- -D warnings` 干净；`gateway_authority`（12 项）与 `gateway_sdk_transport`（24 项）在真实 PostgreSQL 17 下 `--include-ignored` 全通过；lib 370 项不受影响。核实全工作区 `cargo clippy --workspace --all-targets` 目前仍会在 `openbot-testkit` 的 `transport_parity.rs` 处以硬编译错误（E0004，非 clippy 告警）终止，与本次改动无关，系初始快照自带的既有缺口（已用 git stash 在无关干净副本上单独复现确认），已单独归档为 issue #63，未在本 PR 修复范围内。
050 修复 issue #57 记录的既有失败：native_0027.rs / native_0028.rs 各自的幂等重检误用裸 native::apply()（目标随 NATIVE_LATEST_VERSION 漂移），改为 native_0029/native_0033 已确立的 apply_through(client, 自身版本) 写法，未改动任何产品代码。真实 PostgreSQL 17.11 验证：`cargo test -p openbot-infra --test native_0027 --test native_0028 --offline --locked -- --include-ignored` 两项转绿；全 crate `--no-fail-fast -- --include-ignored` 除一项既有、自诊断、与本次无关的环境性失败（schema_baseline_parity.rs 因本机 pg_hba 为 trust 认证无法验证口令是否泄漏，需 scram/md5 实例）外全部通过；两个改动文件的 clippy 干净。

049 修复 archive_bundle.rs::hex_decode 中 `value.len() % 2 != 0` 触发的 clippy::manual_is_multiple_of（issue #58）。该 lint 在当前 rustc/clippy 1.98.0 下会使严格门禁 `cargo clippy --workspace --all-targets --all-features -- -D warnings` 对任何 PR 必现失败，属既有代码、与具体改动无关。改为 `!value.len().is_multiple_of(2)`，语义等价，无行为变化。`cargo clippy -p openbot-infra --lib --offline --locked -- -D warnings` 转绿；`cargo test -p openbot-infra --lib --offline --locked` 370 项通过。修复后补跑全量 `--workspace --all-targets`，发现被该 lib 编译失败长期掩盖的第二波既有红（gateway_authority 测试 9 处 err_expect、gateway_sdk_transport/tls.rs 3 处 dead_code），已登记为 issue #61，作为独立后续任务处理，未在本次改动。

058 Copilot（临时实施执行方，非主控亲验）完成实现与本机验证，待主控独立验收：在完全干净的 `origin/main`（`66274f8`）上逐 crate 补跑测试时，发现 `openbot-agent` 的 `test_official_fixture_provenance_integrity` 既有失败（issue #75，与本次改动前任何工作无关）。根因是 `fixtures/agui/official-event-family.provenance.json` 对 `README.md` 记录的 `bytes`/`sha256` 是过期值（1341 字节），而该文件自本仓库当前历史根提交 `15d66ee` 起实际一直是 231 字节；`git log --oneline --all` 溯源确认 1341 字节仅存在于一个不在 `origin/main` 祖先链上的悬空分支草稿，从未对应过任何真正入库的内容。README.md 是 `vendored_schema` 里唯一标注"OpenBot-authored documentation"（非上游 vendor）的条目，故以当前实际、长期未变的文件内容为准，只更新 `bytes`/`sha256` 两个字段，未碰 `source` 字符串（属 #59/V6-PR-048 命名任务范围）、README.md 正文或其余 6 个已核对无误的 vendor 文件条目。`cargo test -p openbot-agent --all-targets`：58 项 lib 测试 + 5 项 fixture 测试全部通过（此前 4 通过/1 失败）；`cargo clippy -p openbot-agent --all-targets -- -D warnings` 干净。改动范围仅 provenance.json 的 2 行。
## 仍未完成

- 归档容器容量仍是单独预算，不能将 4 MiB 理论明文上限当作外层 8 MiB 容器的可承载保证。
- PostgreSQL/WAL 恢复、隔离暂存的产品装配、同机与新安装恢复演练、签名升级及 A6。
- 旧 0031 数据的合法恢复输入；不能推测旧密文或凭据。
- 稳定签名、真实 OS 权限与旧 Keychain 访问验证。
- SDK 的 App 登录、连接目录、v2 Provider 组合及三种模型完整旅程；PG/Vault 持久授权已由 047 验收，账户桥 Rust 接入与真实厂商旅程仍待完成。
- Browser 与原生电脑的完整产品链、A0–A7 同一候选验收和 24 小时 soak。
- M1 事件与同节点协作、M2 节点与文件能力，以及完整平台、安全和发布验收。
- 严格 Clippy 门禁的第二波既有红（gateway_authority 测试 9 处 err_expect、gateway_sdk_transport/tls.rs 3 处 dead_code，见 issue #61），此前被 049 修复前的 lib 编译失败长期掩盖，从未被 clippy 实际检查到；049 只处理了 issue #58 报告的单点，未处理这批。

040 只验证有界归档的认证消费，不授予恢复切换权限，不关闭以上工作。

## 2026-09-30 独立验收重建检查点

任务编号：REBUILD-20260930-01（公开台账事实纠正）。本任务只同步清点事实，不验收产品候选，不修改任何产品合同。

本轮 GitHub 读取时，远端 main 与本地 main 均为 `66274f8d4e37f8fec018100be7a4b46b7a00a113`。开放任务为 048–058；全部目标 head 已在新机本地 Git 对象库中取回。完整远端分支分页和 PR 搜索未发现后续任务或 060/061 分支；旧候选 SHA 的远端查询返回找不到提交。本轮未合入任何产品候选。

| 任务 | PR | 本轮核对的完整 head SHA | 独立验证尚缺 |
|---|---|---|---|
| 048 | [#59](https://github.com/acosmi/wrokbot/pull/59) | `1528c7338a890cedd0334ea1d3ea91af1445d47e` | 精确命名/冻结身份合同；兼容与范围复核；全候选实测 |
| 049 | [#60](https://github.com/acosmi/wrokbot/pull/60) | `14f3c049d77066b1bbd13ef691fecea267c32a46` | 固定工具链的 infra Clippy 与归档回归 |
| 050 | [#62](https://github.com/acosmi/wrokbot/pull/62) | `bf4f67cb209df5aee3f8bd9a59a88fcdb772408a` | 独立真实 PG 的 0027/0028 重检 |
| 051 | [#64](https://github.com/acosmi/wrokbot/pull/64) | `bfb79b542b02ed470cafa3bbecceccb855cf5859` | 两个共享测试编译单元与真实 PG/TLS |
| 052 | [#67](https://github.com/acosmi/wrokbot/pull/67) | `69ee8fdd59804ef3fa14a972c6fa8a548afef19c` | runtime/launcher feature 和真实 PG 局部装配；不代表完整 Browser |
| 053 | [#68](https://github.com/acosmi/wrokbot/pull/68) | `259fe439453f7da8c78fae94c05368017fc0c30e` | 编译/定向测试与独立 HTTP CRUD 证据 |
| 054 | [#70](https://github.com/acosmi/wrokbot/pull/70) | `776fdb27d2751b89649d515af9167ae6684f3a01` | wasm 构建及真实键盘/DOM 焦点行为 |
| 055 | [#71](https://github.com/acosmi/wrokbot/pull/71) | `86d261c10c13dce9b377ea635a85d8afcb574404` | wasm 与 native Clippy、既有提交状态回归 |
| 056 | [#72](https://github.com/acosmi/wrokbot/pull/72) | `3eeb833c7a8d8157e6879c2ea6a0ff2b79220cb5` | runtime/launcher cfg 与 journal/恢复回归 |
| 057 | [#74](https://github.com/acosmi/wrokbot/pull/74) | `2dfff9a6efcd23b75076a6f748e0ab4d4f4e7aa0` | 固定 rustfmt 已通过；原件及受影响组合回归 |
| 058 | [#76](https://github.com/acosmi/wrokbot/pull/76) | `bf635128e80f2d7831612bfbfbb86d5356466756` | 来源/摘要及 Rust fixture 5/5 已通过；原件与最终候选验收 |

上述 PR 的评论、review、review thread、commit status 及 PR 触发 workflow run 查询均为空。空记录不等于检查通过；本轮没有派发 Actions。#57、#61 虽已关闭，对应 PR #62、#64 仍开放，不能以 issue 关闭推断代码已集成。#56 已按不实施关闭；本轮源码核对确认连接串实际包含口令插值，原先把脱敏展示误诊为字面量的结论不成立。

048 的选定敏感路径字节检查发现 `baseline_0012.sql` 与 `schema_facts.sql` 的说明注释随命名变化；DDL 行为或历史迁移 checksum 是否受影响不得据此臆断，须按精确冻结清单裁定并复验。该候选还涉及 27 个移动端路径，范围许可尚待原件核对。

058 的独立来源核对已完成：候选七份 schema 文件的长度和 SHA-256 均与记录吻合，其中六份上游文件与固定 AG-UI commit 的 Git blob 和原始字节一致；自有 README 为 231 字节，自仓库根提交起字节未变。固定 Rust 1.98.0 上，精确 head `bf635128e80f2d7831612bfbfbb86d5356466756` 的 `cargo test -p openbot-agent --locked --test agui_official_fixture` 实际 5 项通过。main 产品基线 `7edfe6c9849bc6d4e92a18aab12ea90441f1fbba` 的同一测试为 4 项通过、1 项失败，失败是 README 字节记录 1341 与实际 231 不符。源码和独立上游字节支持修复原因；原件合同及最终候选验收仍待，未合入产品候选。

本轮实际运行 `python3 -m unittest tools.test_repository_guard tools.test_tauri_background_assembly_guard`：25 项通过。新机发布 hooks 已启用，Gitleaks 8.30.1 已安装。以上环境与守卫结果不作为 048–058 的 Rust/PG/GUI 验收证据。
固定 Rust 1.98.0 已安装；057 的完整 head 上实际运行 `cargo fmt --all -- --check` 通过。Rust 测试首次尝试因新机 offline 缓存缺少 `subtle` 在依赖解析阶段退出，未执行测试；其后批量 fetch 下载 613 项后中止，转做定向测试；PR #76 首次离线尝试因缺 `ctr` 缓存退出，补齐该专项锁定依赖后实测通过，失败记录保留。上述局部结果不关闭 057 的源码组合复验或其它任务的验收。

060 的四个历史失败用例仍需按冻结的 helper/quiescent/recovery 合同复核，不得为了通过自动删除锁。061 的 macOS helper 当前仍使用 `wait_with_output()`，4096 字节限制发生在收集完成之后；4096/4097、超时/取消、exact Child 清理与失败 journal 尚未在新候选验证。062 的 `--pwprompt` 与 piped stdin 路径仍在；改变测试是否继承 TTY 不构成生产修复。

A0–A7 仍无完整同候选通过证据。SDK App 登录、完整三模型与账户桥、Browser/Engine/画面/GUI、原生产品链、完整 PG/WAL 恢复、签名/真实 OS 和 24 小时验证仍需继续；本轮没有重新取得这些实际结果。下一执行入口为先恢复并核验规范原件与合同，再从最小独立候选开始验收；059/062 继续等待合同裁决。私有规范、合同、交接与原始 QA 不随本台账上传。

任务编号：REBUILD-20260930-02（新机实际验证结果登记）。只更新公开台账，产品代码不变。新机实查为 arm64 / macOS 27.0，固定 Rust 1.98.0 原生工具链、rustfmt、Clippy 已装；仅原生 target 已装。代码签名查询为 0 个有效身份，PATH 和 Homebrew PG17 候选位置未找到 PostgreSQL 二进制。048–058 与前次台账合入后的 main 的合并树冲突都仅在本台账，后续各任务需逐段保留事实解决；此事实不替代验收，也不扩大产品合同。

任务编号：REBUILD-20260930-03（已合并分支清理与验证阻塞登记）。按用户本轮明确要求，清理前逐项核对 48 个非 main 分支的本地与远端 head 一致、均为 main 的祖先、同名 head 已保存在经实际还原核验的本机 Git bundle 中。随后普通原子推送删除这 48 个远端分支，再以 `git branch -d` 删除对应本地分支；未强推或删除未合并候选。定向验证用的三个临时 worktree 均在确认无修改后正常移除，原始证据单独保留。清理检查点 `6ef58727ca982978eba96186254ada1368835169` 的本地与远端仅保留 main 和 048–058 的 11 个候选分支；main 工作树干净。此次台账分支合入后同样清理。

049 精确 head `14f3c049d77066b1bbd13ef691fecea267c32a46` 已尝试固定 Rust 1.98.0 的 infra lib 严格 Clippy：offline 因缺少锁定依赖退出 101；在线尝试因 `num-cmp 0.1.0` 下载超时退出 101。未取得源码 Clippy 结论或归档回归通过证据，失败记录保留。新机可安装的部分原生库版本与仓库构建守卫固定版本不同；未放宽守卫或替换为浮动版本。

用户补充输入材料可能在本仓库或附件。本轮已读取全部 78 条 issue/PR 正文和 11 条讨论评论，未发现规范附件链接；可访问的 Release、tag、Actions 制品、代码评论和提交评论列表均为空。已取回代码历史也未找到规范原件和原始交接入口。规范与冻结合同仍须可信原件核验；该搜索结果不等于规范不存在，也不把历史 PR 当成规范批准。048–058 继续保留待验状态，060/061 未重建，059/062 未批准。当前没有 A0–A7 的完整同候选通过证据。

已建立本机私有 START 入口、执行队列和逐项报告，Git bundle 实际还原核验通过；私有交接包可取回索引与本轮证据。仅有本机副本，未创建或验证离机备份；私有内容不进入本 PR。

## 058 新机独立验收

本轮随后取得并在本机核对后端规范原件；此前“原件未恢复”为当时检查点。精确命名接口仍未冻结，048 保留待验，不以候选代码倒推批准。

058 的产品差异仅为自有 fixture README 的 byte_length 与 sha256 两个过期记录。README、六份上游 schema、上游 commit 和协议身份不改；自有 README 的 231 字节与摘要已独立读取，上游六份文件逐一核对固定来源。原交付提交 `83399e77cfa9a8874cf46ce004b8511ef7eafe84` 为历史实施记录，其自报测试不继承为本轮证据。合入当前 main 的台账时逐段保留双方历史和新机核实事实；合入当前 main 后的候选 `50a27f507f29e96cf59e1d3a1c61546eaff82a34` 在固定 Rust 1.98.0 上运行 `cargo test -p openbot-agent --offline --locked --test agui_official_fixture`：5 项通过，0 失败；修改只涉及两项来源记录和公开台账，未改变测试断言或 schema。后续台账登记提交仍须在推送前对最终 head 复验同一测试。该局部验收不关闭 A0–A7。

## 049 新机候选更新

原交付 `a86d4cbdf89c63f31e4fde5b695ab39fe8a2d3c0` 的历史记录保留，本轮不继承其自报通过数字。产品差异仍为等价的长度奇偶判断；固定原生依赖已在隔离的本机目录构建，来源版本和摘要保持，候选 `2ca120c25b09603995f394a534bfe3e40fbc7098` 在固定 Rust 1.98.0 下，默认 feature 的 infra lib 严格 Clippy 通过，`backup::archive_bundle` 归档读写/完整认证/预算回归 30 项通过、0 失败。定向运行采用已校来源的隔离原生库，未改依赖、扩大 allow、删断言或改字节格式；这不等于完整发行闭包验收。台账登记后的最终 head 推送前复验同两项命令。058 的实际远端合并 SHA 已取回并同步上表；其已合分支及工作树在备份实际还原核验后正常清理。

## 050 新机候选更新

原交付 `ca0fb30f94820a3d5dc850535e5a2a09be3fce75` 的历史记录保留，本轮不继承自报测试。产品生产代码、DDL、schema fixture及断言均不改；两处历史重检仅指定本测试已施加的版本，以核对同版本幂等。已验049实际合并记录已同步，独立 PostgreSQL 17.11 / TCP SCRAM 已核实际版本，错口令确实拒绝，测试集群均正常停止且无 postmaster.pid 残留。基线 `45a0c4a7ac826b47884cd313f6313b461cf41379` 两项均真实失败于历史版本重检；候选 `41cffe0658e31ec04b2ac3068f54999cd9f3e5d6` 两项均通过，两个测试 target 的严格 Clippy 通过。台账登记后的最终 head 推送前复验同两项命令。该局部验证不证明完整产品恢复或 A 门通过。

051 换机主控返修与实际验证：九处等价 expect_err 保留；Client 错误路径改显式 match，不要求存活凭据对象 Debug。共享 TLS fixture 的 HTTP framing 实际消费 Capture.headers，服务器直接消费自身持有的失败计数器；chat_text 原字节移到唯一消费的 SDK 测试入口。原候选四处新增 allow 全部移除，断言、HTTP 算法、TLS 计划及产品代码保持。固定 Rust 1.98.0、offline/locked 两个测试目标严格 Clippy 通过；独立 PG 17.11/TCP SCRAM 的 12 项 authority 显式 include-ignored 全通过，自有 TLS 24 项全通过。首次默认启动 authority 12 项 ignored 如实保留，未记作通过；最终候选重新执行完整 36 项。此结论不代表真实登录、厂商模型或 A2 完成。
