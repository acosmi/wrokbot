//! 环境变量的**读法** —— 解析器一律不碰进程环境。
//!
//! # 为什么解析器不许调 `std::env::var`
//!
//! 一个读进程环境的解析器，它的测试就是**对不受控的全机状态下断言**：同一条用例搬到
//! 另一台机器、或与另一条用例并发跑，答案会翻。这不是理论担忧 —— CrabCode 侧已经为
//! 这个形态吃过一次实测的亏（进程级 env 的互斥组没名字，两个模块互相清空对方的表）。
//!
//! 所以本模块把"进程环境"降级成一个**普通入参**：一张 [`EnvMap`]。解析函数是纯函数，
//! 测试直接构造那张表，既不需要互斥锁，也不会被 shell 里的残留变量污染。
//!
//! 唯一允许触碰 `std::env` 的地方是 [`env_map_from_process`]，它由二进制入口调用一次，
//! **不被任何测试调用** —— 这条不是靠自觉，[`crate::config`] 的
//! `parsers_never_touch_the_process_environment` 用源码级判据钉住它。
//!
//! # 三个原语，逐条对齐上游
//!
//! | 本模块 | 上游 | 语义 |
//! | --- | --- | --- |
//! | [`optional`] | `server/src/config.ts::optional` | `trim()` 后空串**等同未设** |
//! | [`comma_separated`] | `server/src/config.ts::commaSeparated` | 逗号切分、逐项 trim、丢空项 |
//! | [`strip_trailing_slashes`] | `loadConfig` 里的 `.replace(/\/+$/, "")` | 剥尾部斜杠 |
//!
//! "空串等同未设"这条看着琐碎，但它是上游好几条测试的判据：`AGENT_STALL_TIMEOUT_MS=""`
//! 是"关掉看门狗"而不是"写错了"，`GOOGLE_OAUTH_CLIENT_SECRET=""` 是"没配"从而触发
//! 「两个必须同设」的拒绝。把它实现成 `contains_key` 会让这两条同时反向。

use std::collections::BTreeMap;

use openbot_domain::text::trim_ecmascript;

/// 一次启动看见的全部环境变量。
///
/// `BTreeMap` 而不是 `HashMap`：错误报告要把所有毛病一次列全（见
/// [`crate::config::error::ConfigError`]），而一份**顺序随哈希种子变化**的清单，
/// 两次启动会打印出不同顺序的同一批问题，运维没法拿它做 diff。有序遍历让
/// "配置里所有毛病"成为一个确定的、可比对的产物。
pub type EnvMap = BTreeMap<String, String>;

/// 读一个可选变量：两侧 `trim`，空串**等同未设**。
///
/// 返回借用而不是 `String`：调用方多半只是拿去比一下或再切一刀，多一次分配没有意义。
#[must_use]
pub fn optional<'a>(env: &'a EnvMap, name: &str) -> Option<&'a str> {
    let value = trim_ecmascript(env.get(name)?);
    if value.is_empty() { None } else { Some(value) }
}

/// 逗号分隔的列表：切分 → 逐项 `trim` → 丢掉空项。
///
/// 丢空项是有意的，不是宽容：`TRUSTED_ORIGINS="a,,b,"` 里那两个空位不是"一个空 origin"
/// （那种东西不存在），而是人手写 `.env` 时的常见手滑。上游同样丢弃它们，
/// 而"一个空字符串 origin"若被保留，会在 origin 比对处变成一个恒不匹配的幽灵条目。
#[must_use]
pub fn comma_separated(env: &EnvMap, name: &str) -> Vec<String> {
    optional(env, name)
        .unwrap_or_default()
        .split(',')
        .map(trim_ecmascript)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 剥掉尾部**所有**斜杠。
///
/// 公共地址是要和 IdP 处登记的 redirect URI 逐字符比对的（v3 §6.2 条 3），
/// 而 `https://x` 与 `https://x/` 在那个比对里是两个不同的串。上游用
/// `.replace(/\/+$/, "")` 统一到"无尾斜杠"这一侧，这里逐字照搬 —— 两边各自规范化
/// 到不同的一侧，就是一个只在生产才炸的登录失败。
#[must_use]
pub fn strip_trailing_slashes(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// **本仓唯一**允许读取进程环境的函数。
///
/// # 谁可以调它
///
/// 只有二进制入口，在启动时调用**一次**，把结果交给各个 `from_env_map`。
///
/// # 谁不可以调它
///
/// **任何测试。** 理由见模块文档：一条读进程环境的断言测的不是代码，是这台机器此刻的
/// shell。[`crate::config`] 里的 `parsers_never_touch_the_process_environment`
/// 会在其余解析文件里出现 `std::env` 时当场判红。
///
/// # 非 UTF-8 的名字与值
///
/// Windows 上环境变量可以不是合法 Unicode。这里走 `vars_os` 并对两侧做 lossy 转换，
/// **而不是把这一条跳过** —— 跳过等于"读不到就当没设"，而 v3 §15.4 末句对退役变量
/// 逐字禁止这一条：一个值是乱码的退役变量，必须仍然被
/// [`crate::config::migration::check_migrated_env_vars`] 看见。
/// lossy 之后的值不可能悄悄通过任何一条校验（base64、URL、整数都会拒），
/// 所以这个方向是响亮失败而不是静默放行。
#[must_use]
pub fn env_map_from_process() -> EnvMap {
    std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// 空串等同未设 —— 并配"非空确实读得到"的正向对照。
    ///
    /// 没有那条正向对照的话，一个恒返回 `None` 的 `optional` 也能过。
    #[test]
    fn blank_is_absent_and_a_real_value_is_not() {
        let map = env(&[
            ("EMPTY", ""),
            ("SPACES", "   "),
            ("BOM", "\u{FEFF}\u{3000}"),
            ("REAL", "\u{FEFF} v \u{3000}"),
            ("NEL", "\u{0085}v\u{0085}"),
        ]);
        assert_eq!(optional(&map, "EMPTY"), None);
        assert_eq!(optional(&map, "SPACES"), None);
        assert_eq!(optional(&map, "BOM"), None);
        assert_eq!(optional(&map, "MISSING"), None);
        // 正向对照：有值时确实读得到，而且两侧已 trim。
        assert_eq!(optional(&map, "REAL"), Some("v"));
        assert_eq!(
            optional(&map, "NEL"),
            Some("\u{0085}v\u{0085}"),
            "U+0085 不能借 Rust White_Space 冒充 ECMAScript WhiteSpace"
        );
    }

    /// 逐项 trim + 丢空项 —— 并配"正常列表原样保留顺序"的正向对照。
    #[test]
    fn comma_separated_drops_blanks_and_keeps_order() {
        let map = env(&[
            ("LIST", " a , ,b,, c ,"),
            ("ONE", "solo"),
            ("BLANK", " , "),
            ("ECMA", "\u{FEFF}a\u{3000},\u{0085}b\u{0085}"),
        ]);
        assert_eq!(comma_separated(&map, "LIST"), vec!["a", "b", "c"]);
        assert_eq!(
            comma_separated(&map, "ECMA"),
            vec!["a", "\u{0085}b\u{0085}"]
        );
        // 正向对照：单项与缺失各自给出应有的形状，否则上一条在
        // "comma_separated 恒返回空表"的世界里同样通过。
        assert_eq!(comma_separated(&map, "ONE"), vec!["solo"]);
        assert!(comma_separated(&map, "BLANK").is_empty());
        assert!(comma_separated(&map, "MISSING").is_empty());
    }

    /// 尾斜杠全剥，中间的一律不动。
    #[test]
    fn trailing_slashes_go_and_nothing_else_does() {
        assert_eq!(
            strip_trailing_slashes("https://x.test///"),
            "https://x.test"
        );
        assert_eq!(strip_trailing_slashes("https://x.test"), "https://x.test");
        // 正向对照：路径里的斜杠不能被顺手吃掉。
        assert_eq!(
            strip_trailing_slashes("https://x.test/api/auth/"),
            "https://x.test/api/auth"
        );
    }
}
