//! 配置里的机密值 —— 一个**不会被 `Debug` 打印出来**的字符串。
//!
//! # 为什么值得一个类型
//!
//! v3 §6.4 末段逐字列了一串"永不进入普通日志、trace、metric、crash dump"的值，
//! `COMPUTER_TOKEN`（computer bootstrap secret）就在其中。而 [`crate::config::ServerConfig`]
//! 是个会被 `tracing::debug!` 顺手打出来的启动产物 —— `#[derive(Debug)]` 一加，
//! 那条禁令就在**没有任何人做决定**的情况下被违反了。
//!
//! 用类型而不是纪律来兑现它：机密字段的类型自己不肯打印，于是"忘了"这件事不再可能发生。
//! 新增一个机密字段时也不需要记得去改 `Debug` 实现 —— 只要它的类型是 [`Secret`]，
//! 默认就是安全的。
//!
//! # 已知的重复，交付时请一并看
//!
//! `openbot-infra::auth::config` 有一个同名同形的类型。两个 crate 是**兄弟**（谁也不依赖谁），
//! 所以此刻没有共同落点。正确的归宿是 `openbot-contracts` 或 `openbot-domain`；
//! 合并是集成层的动作，不是本模块能顺手做的。

use core::fmt;

/// 一个不进日志的配置值。
///
/// `Debug` 恒印 `Secret(***)`，且**刻意不实现 `Display`**：一个能直接 `{}` 出来的机密
/// 类型等于没有类型。需要真值的地方必须显式调 [`Secret::expose`]，那一行在 review 里
/// 是显眼的。
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    /// 由已经 `trim` 过的非空值构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(zeroize::Zeroizing::new(value.into()))
    }

    /// 取出真值。**调用点即是泄漏面**，只在真正要把它交给对端时使用。
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 字节长度。存在的唯一理由是长度校验（例如 session secret 的 32 字符下限）
    /// 不必先 [`Secret::expose`]。
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。构造路径已排除空值，这里只是让 [`Secret::len`] 不孤零零地存在。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 连长度都不印：长度会泄漏"这是不是那个 44 字符的示例 key"之类的信息，
        // 而它对排障毫无帮助 —— 想知道有没有配上，看的是字段在不在，不是它多长。
        formatter.write_str("Secret(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Debug` 不得泄漏真值 —— 并配"真值确实还在里面"的正向对照。
    ///
    /// 没有正向对照的话，一个把值直接丢掉的实现也能过这条。
    #[test]
    fn debug_redacts_while_the_value_survives() {
        let secret = Secret::new("super-secret-computer-token");
        let printed = format!("{secret:?}");
        assert!(
            !printed.contains("super-secret-computer-token"),
            "{printed}"
        );
        assert_eq!(printed, "Secret(***)");
        // 正向对照：值没被丢掉，只是不肯打印。
        assert_eq!(secret.expose(), "super-secret-computer-token");
        assert_eq!(secret.len(), "super-secret-computer-token".len());
        assert!(!secret.is_empty());
    }

    /// 嵌在别的结构里时同样不泄漏 —— 真实的泄漏形态是
    /// `tracing::debug!("{config:?}")`，而不是有人单独去 `{:?}` 一个 secret。
    #[test]
    fn nesting_does_not_reopen_the_leak() {
        #[derive(Debug)]
        struct Holder {
            token: Secret,
            plain: &'static str,
        }
        let holder = Holder {
            token: Secret::new("leak-me"),
            plain: "not-a-secret",
        };
        // 先证明两个字段确实装着这两个值 —— 否则下面"没泄漏"那条，
        // 在"字段压根没被赋值"的世界里同样通过。
        assert_eq!(holder.token.expose(), "leak-me");
        assert_eq!(holder.plain, "not-a-secret");

        let printed = format!("{holder:?}");
        assert!(!printed.contains("leak-me"), "{printed}");
        // 正向对照：非机密字段照常可见，否则本条在"Holder 的 Debug 什么都不印"
        // 的世界里同样通过。
        assert!(printed.contains("not-a-secret"), "{printed}");
    }
}
