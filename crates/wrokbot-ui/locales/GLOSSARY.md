# Chinese UI terminology

Brand name: Wrok Bot. Keep translations consistent across screens.

| en | zh-CN | 说明 |
| --- | --- | --- |
| Bot | Bot（不译） | 产品自身的名字，任何位置都不翻译 |
| Coworker | 同事 | 用户创建、可配技能的智能体；界面上一律「同事」，不用「代理」「智能体」 |
| Channel | 频道 | 一个协作空间 |
| Thread | 会话 | 频道内的一次完整对话 |
| Run | 运行 | 一次工具 / 技能的执行 |
| Tool | 工具 | 可被调用的能力单元 |
| Skill | 技能 | 用户可编辑、可分配给同事的工具封装 |
| Plugin | 插件 | 第三方扩展包 |
| Connector | 连接器 | 连接外部服务（如 Google Drive）的组件 |
| Computer | 计算机 | 同事可操作的机器；不用「电脑」「桌面」 |
| Deployment | 部署 | |
| Boundary | 边界 | 工具调用的权限 / 数据边界 |
| Credential | 凭据 | 不用「证书」「密钥」（密钥另有其词） |
| Identity provider | 身份提供方 | 不用「身份供应商」 |
| People | 成员 | admin 里的人员列表；不用「人员」「用户」 |
| Grant | 授权 | 名词与动词同形 |
| Approval | 审批 | 不用「批准」（那是动作 Approve） |
| Audit | 审计 | |
| Component | 组件 | 同事渲染出的 UI 组件 |
| Gallery | 组件库 | 组件的浏览页；不用「画廊」 |
| Memory | 记忆 | 不用「内存」 |
| Tenant package | 租户包 | |


`en.json` and `zh-CN.json` must contain identical keys and interpolation parameters. Run `cargo xtask i18n-check` after editing locale files.
