//! `AGENT_COMPUTER_POLICY` —— 一整份 action policy 塞在一个环境变量里。
//!
//! # 为什么它必须在**启动期**解析，而不是等第一次工具调用
//!
//! 上游 `config.ts::actionPolicy` 的注释把理由写得很清楚，原样搬过来：一个写了规则又把它
//! 打错的操作员，否则会得到一个**照常跑着、并且静默放行了他刚刚想禁止的那件事**的部署，
//! 而且没有任何迹象表明哪里不对。
//!
//! 值得说明的是"fail-closed 就够了"这个诱人的想法为什么不够。策略引擎确实是 fail-closed
//! 的：一份加载不了的策略会拒绝一切。但那两种失败对操作员是**完全相反**的观感 ——
//! 启动期拒绝是"你的配置有问题，在这一行"，运行期 fail-closed 是"这个 Bot 突然什么都做不了"。
//! 后者会被当成产品坏了，而不是配置写错了。
//!
//! # 反直觉的一点：**没配 computer 地址时，这个变量根本不被解析**
//!
//! 上游 `config.ts::computerConfig` 在 `COMPUTER_SUPERVISOR_URL` 与 `AGENT_COMPUTER_URL`
//! 都没设时**提前 return**，而 `actionPolicy(environment)` 的调用点在那之后。于是一份
//! 写着 `AGENT_COMPUTER_POLICY={ 语法错误` 但没配任何 computer 地址的环境，
//! 上游是**照常启动**的。
//!
//! 这是本轮实测读出来的，不是推断。本模块照做，理由是"照做"在这里恰好也是对的：
//! computer 能力整体没挂载时，那份策略没有任何东西会去读它，为一个不会被使用的值
//! 拒绝启动，等于让一个可以正常工作的部署起不来。
//!
//! 代价要说清楚：**一个操作员可以把策略写错、部署照常起来、直到他某天配上 computer
//! 地址那一刻才发现。** 所以这一条写进了 [`crate::config::ServerConfig`] 的字段文档，
//! 而不是只活在这里。
//!
//! # 为什么不给 `ActionPolicy` 派生 `Deserialize`
//!
//! v3 §5.2 逐字禁止 transport 接受"自由 JSON 直接铸造领域类型"。一个 `#[derive(Deserialize)]`
//! 的领域类型意味着**任何一段能反序列化的字节都能造出一个领域值**，而领域类型的全部意义
//! 就是"它的每个值都满足某条不变量"。
//!
//! 所以这里逐字段读 [`serde_json::Value`]、逐字段校验、再**显式构造**
//! [`ActionPolicy`]。多写的那二十行就是那条边界本身。

use openbot_domain::policy::{ActionPolicy, PolicyMode};
use serde_json::{Map, Value};

use crate::config::error::Expectation;

/// 解析 `AGENT_COMPUTER_POLICY` 的值。
///
/// # 形状逐条对齐上游 `server/src/computer/policy-store.ts::parseActionPolicy`
///
/// | 字段 | 规则 | 缺省 |
/// | --- | --- | --- |
/// | 顶层 | 必须是 JSON **对象** | 无（必填） |
/// | `mode` | 恰为 `"enforce"` 或 `"dry-run"` | **无缺省**，必填 |
/// | `deny` | 字符串数组 | 缺失或 `null` → 空表 |
/// | `allow` | 字符串数组 | 缺失或 `null` → 空表 |
///
/// `mode` 没有缺省是上游的决定，这里照搬：往哪个方向缺省都会把一份策略变成它的反面
/// （见 [`Expectation::ActionPolicyMode`]）。
///
/// **空的 `allow` 意味着什么都不放行**（`openbot_domain::policy::ActionPolicy::allow` 的
/// 字段文档逐字如此），而不是"没写就全放行"。上游那份 `DEFAULT_ACTION_POLICY`
/// （`allow: ["true"]`）是**没有策略文档**时的缺省，不是"写了策略但没写 allow"时的缺省 ——
/// 这两件事混起来，就会把一份"只写了 deny 的收紧策略"变成一份放行一切的策略。
///
/// # 与上游唯一的诊断差异
///
/// 顶层是 JSON **数组**时：上游 `typeof [] === "object"` 会让它通过第一道检查，然后在
/// `mode` 那道失败，于是报的是 mode 的错；这里报 [`Expectation::ActionPolicyObject`]。
/// **接受集完全相同**（两边都拒绝），差别只在报出来的那句话更准。
///
/// # Errors
///
/// 返回该值**没能满足**的那条期望。变量名由调用方补上 —— 本函数不知道自己在解析哪个变量，
/// 这样它就不可能把变量名写错。
pub fn parse_action_policy(raw: &str) -> Result<ActionPolicy, Expectation> {
    let value: Value = serde_json::from_str(raw).map_err(|_| Expectation::ActionPolicyJson)?;
    let object = value.as_object().ok_or(Expectation::ActionPolicyObject)?;

    // `mode` 必填。`as_str` 同时挡掉"不是字符串"与"不存在"，两者对操作员是同一件事：
    // 这份策略没说它是拦截还是只记录。
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<PolicyMode>().ok())
        .ok_or(Expectation::ActionPolicyMode)?;

    let deny = rule_list(object, "deny").ok_or(Expectation::ActionPolicyDenyList)?;
    let allow = rule_list(object, "allow").ok_or(Expectation::ActionPolicyAllowList)?;

    // 显式构造，不是反序列化 —— 见模块文档最后一节。
    Ok(ActionPolicy { mode, deny, allow })
}

/// 读一个规则列表：缺失或 `null` → 空表；数组且每一项都是字符串 → 收下；其余 → `None`。
///
/// `null` 与缺失同义是上游 `candidate[key] ?? []` 的语义（`??` 对 `null` 与 `undefined`
/// 都触发）。**不**把 `false` / `0` / `""` 当空表 —— 那些在上游会走到 `Array.isArray`
/// 那一关并失败，这里同样失败。
fn rule_list(object: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    match object.get(key) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一份完整策略逐字段读出来 —— 本组的正向对照。
    #[test]
    fn a_complete_policy_round_trips_every_field() {
        let policy = parse_action_policy(
            r#"{"mode":"dry-run","deny":["tool.name == \"computer_key\""],"allow":["true"]}"#,
        )
        .expect("合法策略");
        assert_eq!(policy.mode, PolicyMode::DryRun);
        assert_eq!(policy.deny, vec!["tool.name == \"computer_key\""]);
        assert_eq!(policy.allow, vec!["true"]);

        // 另一档也读得出来，否则上一条在"mode 恒为 DryRun"的世界里同样通过。
        let enforcing =
            parse_action_policy(r#"{"mode":"enforce","allow":["true"]}"#).expect("合法策略");
        assert_eq!(enforcing.mode, PolicyMode::Enforce);
    }

    /// 两个列表缺失或为 `null` 时都是空表，**不是**"放行一切"。
    #[test]
    fn absent_rule_lists_are_empty_not_permissive() {
        for raw in [
            r#"{"mode":"enforce"}"#,
            r#"{"mode":"enforce","deny":null,"allow":null}"#,
            r#"{"mode":"enforce","deny":[],"allow":[]}"#,
        ] {
            let policy = parse_action_policy(raw).unwrap_or_else(|_| panic!("{raw} 应当合法"));
            assert!(policy.deny.is_empty(), "{raw}");
            assert!(policy.allow.is_empty(), "{raw}");
        }

        // 正向对照：写了内容时确实收得进来 —— 否则上面在"两个列表恒为空"的世界里同样通过。
        let filled =
            parse_action_policy(r#"{"mode":"enforce","deny":["a"],"allow":["b"]}"#).expect("合法");
        assert_eq!(filled.deny, vec!["a"]);
        assert_eq!(filled.allow, vec!["b"]);
    }

    /// 非法 JSON 与非对象顶层，各报各的。
    #[test]
    fn malformed_json_and_non_objects_are_told_apart() {
        for bad in ["{ this is not json", "", "{\"mode\":", "tru"] {
            assert_eq!(
                parse_action_policy(bad),
                Err(Expectation::ActionPolicyJson),
                "{bad:?}"
            );
        }
        for not_an_object in ["[]", r#"["mode"]"#, "42", "\"enforce\"", "null", "true"] {
            assert_eq!(
                parse_action_policy(not_an_object),
                Err(Expectation::ActionPolicyObject),
                "{not_an_object:?}"
            );
        }
    }

    /// `mode` 必填，且只认那两个字面量。
    ///
    /// 取值域是落库的字节（`action_policy.mode` 是 text 不是 enum），所以不做大小写宽容 ——
    /// 收下一个 `"Enforce"` 就等于让数据库里出现第三个取值。
    #[test]
    fn mode_is_required_and_read_exactly() {
        for bad in [
            r#"{}"#,
            r#"{"deny":[],"allow":[]}"#,
            r#"{"mode":null}"#,
            r#"{"mode":"Enforce"}"#,
            r#"{"mode":"ENFORCE"}"#,
            r#"{"mode":"dryrun"}"#,
            r#"{"mode":"dry_run"}"#,
            r#"{"mode":"audit"}"#,
            r#"{"mode":true}"#,
            r#"{"mode":1}"#,
            r#"{"mode":["enforce"]}"#,
        ] {
            assert_eq!(
                parse_action_policy(bad),
                Err(Expectation::ActionPolicyMode),
                "{bad:?}"
            );
        }

        // 正向对照：两个合法取值确实都收 —— 否则上面在"mode 永远读不出来"的世界里同样通过。
        assert_eq!(
            parse_action_policy(r#"{"mode":"enforce"}"#)
                .expect("合法")
                .mode,
            PolicyMode::Enforce
        );
        assert_eq!(
            parse_action_policy(r#"{"mode":"dry-run"}"#)
                .expect("合法")
                .mode,
            PolicyMode::DryRun
        );
    }

    /// 两个规则列表各报各的 code —— 运维要知道是哪一个列表写错了。
    #[test]
    fn each_rule_list_reports_its_own_expectation() {
        for (raw, expected) in [
            (
                r#"{"mode":"enforce","deny":"true"}"#,
                Expectation::ActionPolicyDenyList,
            ),
            (
                r#"{"mode":"enforce","deny":[1]}"#,
                Expectation::ActionPolicyDenyList,
            ),
            (
                r#"{"mode":"enforce","deny":[null]}"#,
                Expectation::ActionPolicyDenyList,
            ),
            (
                r#"{"mode":"enforce","deny":{}}"#,
                Expectation::ActionPolicyDenyList,
            ),
            (
                r#"{"mode":"enforce","deny":false}"#,
                Expectation::ActionPolicyDenyList,
            ),
            (
                r#"{"mode":"enforce","allow":"true"}"#,
                Expectation::ActionPolicyAllowList,
            ),
            (
                r#"{"mode":"enforce","allow":[1]}"#,
                Expectation::ActionPolicyAllowList,
            ),
            (
                r#"{"mode":"enforce","allow":["ok",2]}"#,
                Expectation::ActionPolicyAllowList,
            ),
        ] {
            assert_eq!(parse_action_policy(raw), Err(expected), "{raw:?}");
        }

        // 两条 code 确实不同 —— 否则上面那组分不出 deny 与 allow。
        assert_ne!(
            Expectation::ActionPolicyDenyList.as_str(),
            Expectation::ActionPolicyAllowList.as_str()
        );
    }

    /// 未知字段被忽略，与上游一致（它只读 `mode` / `deny` / `allow` 三个键）。
    #[test]
    fn unknown_fields_are_ignored_like_upstream() {
        let policy =
            parse_action_policy(r#"{"mode":"enforce","allow":["true"],"future_field":123}"#)
                .expect("上游同样忽略它不认识的键");
        assert_eq!(policy.allow, vec!["true"]);
    }

    /// `.env.example` 里那份示例策略解得开。
    ///
    /// 它是操作员最可能直接抄走的那一份，所以它必须是本模块的一条用例 ——
    /// 一个解不开示例的解析器，第一次被用到就会失败。
    #[test]
    fn the_shipped_example_policy_parses() {
        // 逐字取自上游 `.env.example` 的 `AGENT_COMPUTER_POLICY=` 一行（去掉注释前缀）。
        let raw = r#"{"mode":"enforce","deny":["(intent == \"activate\" && contains(element.name, \"submit\")) || ((tool.name == \"computer_key\" || tool.name == \"computer_type\") && key == \"Enter\")"],"allow":["true"]}"#;
        let policy = parse_action_policy(raw).expect("上游随包发的示例必须解得开");
        assert_eq!(policy.mode, PolicyMode::Enforce);
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.allow, vec!["true"]);
        // 表达式原文原样保留：本层不解析 CEL，那是 `CompiledActionPolicy::compile` 的活。
        assert!(
            policy.deny[0].contains("computer_key"),
            "{:?}",
            policy.deny[0]
        );
    }
}
