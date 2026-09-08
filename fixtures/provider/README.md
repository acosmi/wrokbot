# Provider recorded traces

本目录只保存 provider 官方发布或由受控 live 录制后完成消毒的原始响应字节，以及一对一的
`*.provenance.json`。手写 test double、官方文档里的片段和依据 schema 合成的 JSON 不能标成
recorded trace。

每份 provenance 必须固定：provider、协议/endpoint、来源 commit/blob、原记录字节数与 SHA-256、
fixture 字节数与 SHA-256、取得时间、消毒规则、许可证与 copyright。fixture 不得包含请求正文、
Authorization/API key、账号/项目标识、客户数据或可验证 secret hash。

`.sse` 保留 vendor response body 的原始 LF 字节，包括最后一个事件的空行分隔符；因此
`.gitattributes` 只对该格式关闭 `blank-at-eof`，仍保留其余 whitespace 与 LF 检查。不得为让
`git diff --check` 安静而删除协议字节。

验收必须从 loopback HTTP 经过 production adapter 与唯一 SafeDialer 离线回放，而不是直接调用
decoder。至少同时比较整块、非规则分块与逐字节分块的 normalized event 序列，并验证 malformed
vendor body 不进入 Debug/错误/audit。recorded fixture 与 test-only mutation 必须分开标注。
