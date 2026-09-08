//! 核心 ID（v3 §5.3）。
//!
//! §5.3 逐字规定：「所有 ID 是 string newtype，不擅自限定为 UUID；创建端可以使用
//! UUIDv7/ULID，兼容端必须接受上游既有字符串。」十五个**核心/对外**名字由 §5.3 的表
//! 固定。D-2 另把已经跨 crate 的 `AttemptId` / `CapabilityId` / `CatalogGeneration`
//! 收口到本模块；它们是内部跨层 contract，不冒充第十六至十八个公开 wire ID。
//!
//! # 为什么 `ComputerGeneration` / `DocumentGeneration` 是 `u64` 而不是 `String`
//!
//! reviewer裁决 D7，理由是第一性的，不是口味：
//!
//! 1. §11.2 的 `EngineCommand` 与 §12.3 的 `FrameHeader` 两个结构体里，generation 字段
//!    本身就写作 `pub generation: u64` —— 把它做成 string newtype 会在协议边界上强制
//!    一次字符串 ↔ 数值转换，而转换失败在帧头解析这种热路径上没有正确的降级答案。
//! 2. 「旧 generation 全失效」（§17.2 条 6）这条不变量依赖**数值序**。字符串的字典序
//!    会给出错误答案：`"10" < "9"`。用字符串承载序关系 = 把不变量建在会撒谎的比较上。
//! 3. §5.3 那条 string 规则给出的理由是「兼容端必须接受上游既有字符串」，而 generation
//!    **不是上游提供的标识符** —— 它是本系统自己单调递增铸造的计数器，没有任何上游
//!    既有取值需要兼容。规则的适用前提在这两个类型上不成立。
//!
//! 其余十三个是 `String` newtype，逐字遵守 §5.3。

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// RFC 9562 UUIDv8 thread identity 布局与 deployment 归属判定。
pub mod thread;

/// 生成 string newtype ID。
///
/// 十三个类型的实现逐字相同，手抄十三份的唯一结果是十三份各自漂移的机会 ——
/// 宏让「所有 string ID 行为一致」成为构造性事实而不是需要复核的约定。
macro_rules! define_string_ids {
    ($($(#[$attr:meta])* $name:ident),+ $(,)?) => {
        $(
            $(#[$attr])*
            ///
            /// **不做任何格式 / 长度 / 字符集校验**（v3 §5.3）：创建端可以铸造 UUIDv7 / ULID，
            /// 兼容端必须原样接受上游既有字符串。加校验 = 把上游既有数据判成非法，正是 §5.3
            /// 逐字禁止的「擅自限定」。
            #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                /// 由任意可转 `String` 的值构造。刻意不校验，理由见类型文档。
                #[must_use]
                pub fn new(value: impl Into<String>) -> Self {
                    Self(value.into())
                }

                /// 借出底层字符串。
                #[must_use]
                pub fn as_str(&self) -> &str {
                    self.0.as_str()
                }

                /// 交出底层字符串的所有权。
                #[must_use]
                pub fn into_inner(self) -> String {
                    self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(self.0.as_str())
                }
            }

            impl AsRef<str> for $name {
                fn as_ref(&self) -> &str {
                    self.0.as_str()
                }
            }

            impl FromStr for $name {
                // 永不失败：没有任何格式约束可供违反（§5.3）。`Infallible` 让「解析 ID 可能
                // 失败」这个念头在类型层面就不存在，调用点不会长出一条恒不命中的错误分支。
                type Err = Infallible;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Ok(Self::new(value))
                }
            }
        )+
    };
}

/// 生成 `u64` newtype ID（generation 计数器）。
macro_rules! define_u64_ids {
    ($($(#[$attr:meta])* $name:ident),+ $(,)?) => {
        $(
            $(#[$attr])*
            ///
            /// `u64` 而非 string newtype，理由见本模块文档（裁决 D7）：协议结构体里它就是
            /// `u64`，而且「旧 generation 失效」依赖数值序 —— 字典序会判 `"10" < "9"`。
            #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
            #[serde(transparent)]
            pub struct $name(u64);

            impl $name {
                /// 由原始计数值构造。
                #[must_use]
                pub const fn new(value: u64) -> Self {
                    Self(value)
                }

                /// 取出原始计数值。
                #[must_use]
                pub const fn get(self) -> u64 {
                    self.0
                }

                /// 铸造下一个 generation。
                ///
                /// 用 `saturating_add(1)` 而不是 `+ 1`：`+` 在 debug 下溢出 panic、在 release 下
                /// **回绕到 0**，而回绕比饱和危险得多 —— generation 0 会让一个早已陈旧的值
                /// 重新成为「最新」，直接击穿 §17.2 条 6「engine restart/reset 使旧 generation
                /// 全失效」。饱和的最坏结果是停在 `u64::MAX` 不再前进，此时任何 stale 判定
                /// 仍然为真（fail-closed）。
                ///
                /// 因此这里既不 panic 也不回绕：u64 到顶需要每纳秒铸造一次连续跑约 584 年，
                /// 实践中不可达；真到顶时正确行为是「停住并继续判旧」，不是崩溃或复用。
                #[must_use]
                pub const fn next(self) -> Self {
                    Self(self.0.saturating_add(1))
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(&self.0, f)
                }
            }
        )+
    };
}

/// 一次工具执行尝试的标识。
///
/// §17.2 条 2 的 durable decision 与 attempt 是两行：decision 说“允许”，attempt 说
/// “本次开始做了”；一次 decision 可对应多次安全重放尝试。
/// 跨 domain/application/infra，因此由 contracts 单点定义；不实现 serde / Display，
/// 避免被顺手塞进对外 DTO 或日志。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(String);

impl AttemptId {
    /// 从既有标识构造；兼容端不加格式限制。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// 单次能力券的内部标识。
///
/// 它参与 repository CAS 与 application 调用，但不是模型/浏览器可铸造的 wire 值，
/// 所以与 [`AttemptId`] 一样刻意不实现 serde / Display。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// 从内部铸造值构造。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// tool catalog 的数值代际。refresh 后旧 approval/capability 必须失效。
///
/// 用 `u64` 是因为失效判定依赖数值序；字典序会错判 `"10" < "9"`。
/// 不实现 serde：它是 Rust 内部状态轴，不是让外部声明“我属于第几代”的输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogGeneration(u64);

impl CatalogGeneration {
    /// 从权威计数值构造。
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// 取出数值。
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

define_string_ids! {
    /// 一次部署的身份。`DEPLOYMENT_ID` 是 thread id 六字节指纹的来源（§15.4），
    /// 改它等于放弃对既有 thread 的 `owns` 判定。
    DeploymentId,
    /// 租户。多用户 Server 的一切 scope 判定都以它为最外层（§17.2 条 12）。
    TenantId,
    /// 行动者（人或 Agent）。高基数，只进受控 trace/log，不进 metrics label（§16.4）。
    ActorId,
    /// Bot。
    BotId,
    /// Channel。对当前 actor 不可见时统一回 404，不区分「不存在」与「无权」（§15.3）。
    ChannelId,
    /// 会话线程。高基数，不进 metrics label（§16.4）。
    ThreadId,
    /// 一次 Agent run。
    RunId,
    /// 一次工具调用。
    ToolCallId,
    /// 凭据主体。`ProfileScope = tenant + bot + credential_principal`，profile 不跨它（§17.2 条 5）。
    CredentialPrincipalId,
    /// 一台受监管的 computer（browser engine 宿主）。
    ComputerId,
    /// browser tab。
    TabId,
    /// 一次 policy 裁决。它是 audit 链上「acting 之前有 durable decision」的锚（§17.2 条 2）。
    PolicyDecisionId,
    /// 一条 audit 事件。
    AuditEventId,
}

define_u64_ids! {
    /// computer 的代际计数。engine restart/reset 递增它，旧代际的 ref / ticket / approval /
    /// capability / lease 全部失效（§17.2 条 6）。
    ComputerGeneration,
    /// document（页面）的代际计数。snapshot ref 绑定它（§17.2 条 4）。
    DocumentGeneration,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SerializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> SerializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::Serialize> SerializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait SerializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> SerializeProbeFallback for SerializeProbe<T> {}

    struct DeserializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> DeserializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait DeserializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> DeserializeProbeFallback for DeserializeProbe<T> {}

    /// 内部跨层 ID 进 contracts 不等于进 wire；核心 ID 作正向对照仍可 serde。
    #[test]
    fn internal_contract_ids_are_not_serializable_wire_types() {
        assert!(!SerializeProbe::<AttemptId>::new().is_implemented());
        assert!(!SerializeProbe::<CapabilityId>::new().is_implemented());
        assert!(!SerializeProbe::<CatalogGeneration>::new().is_implemented());
        assert!(!DeserializeProbe::<AttemptId>::new().is_implemented());
        assert!(!DeserializeProbe::<CapabilityId>::new().is_implemented());
        assert!(!DeserializeProbe::<CatalogGeneration>::new().is_implemented());
        assert!(SerializeProbe::<ActorId>::new().is_implemented());
        assert!(DeserializeProbe::<ActorId>::new().is_implemented());
    }

    /// §5.3「兼容端必须接受上游既有字符串」的直接兑现：一个明显不是 UUID 的上游风格
    /// 字符串必须构造成功且**逐字节原样保留**。
    ///
    /// 这是负向对照（证明「没有校验」）；它的正向对照是同一批断言里
    /// `uuid_shaped_and_ulid_shaped_ids_are_equally_accepted` —— 如果本类型压根不能构造
    /// 任何值，两条测试会一起红，而不是只有一条恒绿。
    #[test]
    fn upstream_style_non_uuid_ids_are_accepted_verbatim() {
        let id = ChannelId::new("legacy-channel-42");
        assert_eq!(id.as_str(), "legacy-channel-42");
        assert_eq!(id.to_string(), "legacy-channel-42");
        assert_eq!(id.clone().into_inner(), "legacy-channel-42");

        // 空串、含空格、超长、非 ASCII —— 一律不拒绝。任何一条被拒都说明有人加了校验。
        assert_eq!(ThreadId::new("").as_str(), "");
        assert_eq!(ActorId::new("a b\tc").as_str(), "a b\tc");
        assert_eq!(BotId::new("机器人-一号").as_str(), "机器人-一号");
        assert_eq!(RunId::new("x".repeat(4096)).as_str().len(), 4096);
    }

    /// 正向对照：创建端偏好的 UUIDv7 / ULID 形态同样被接受，证明上一条不是靠「什么都
    /// 构造不出来」蒙混过关。
    #[test]
    fn uuid_shaped_and_ulid_shaped_ids_are_equally_accepted() {
        let uuid = "0199a4d1-6f2b-7c3e-8a11-0242ac120002";
        let ulid = "01J9ZK8H4T7Q2M6VXB3RN5CDEF";
        assert_eq!(TenantId::new(uuid).as_str(), uuid);
        assert_eq!(TenantId::new(ulid).as_str(), ulid);
        assert_eq!(TenantId::from_str(uuid).unwrap().as_str(), uuid);
    }

    #[test]
    fn string_id_serde_is_transparent() {
        let id = PolicyDecisionId::new("pd-1");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"pd-1\"");
        let back: PolicyDecisionId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn u64_generation_serde_is_transparent() {
        let gen_ = ComputerGeneration::new(7);
        let json = serde_json::to_string(&gen_).unwrap();
        assert_eq!(json, "7");
        let back: ComputerGeneration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, gen_);
        assert_eq!(gen_.get(), 7);
        assert_eq!(gen_.to_string(), "7");
    }

    /// 裁决 D7 的判据本身：数值序正确，而同一对值的字典序是错的。
    /// 这条测试是 D7 的可执行证据，删掉它等于把理由退回成口头说明。
    #[test]
    fn generation_orders_numerically_not_lexicographically() {
        let nine = DocumentGeneration::new(9);
        let ten = DocumentGeneration::new(10);
        assert!(nine < ten, "数值序必须判 9 < 10");

        // 正向对照：如果 generation 曾被做成 string newtype，同一对值会给出相反答案。
        assert!(
            "10" < "9",
            "字典序确实判 \"10\" < \"9\" —— 这正是不能用字符串的理由"
        );
    }

    #[test]
    fn generation_next_saturates_instead_of_wrapping() {
        assert_eq!(ComputerGeneration::new(0).next().get(), 1);
        // 回绕会得到 0（重新变成"最新"）；饱和停在 MAX（继续判旧）。
        assert_eq!(
            ComputerGeneration::new(u64::MAX).next().get(),
            u64::MAX,
            "到顶必须饱和；回绕到 0 会让陈旧代际复活"
        );
    }

    #[test]
    fn string_id_from_str_is_infallible() {
        let parsed: Result<AuditEventId, Infallible> = "ae-1".parse();
        assert_eq!(parsed.unwrap().as_str(), "ae-1");
    }

    /// 各 ID 是**互不相同**的类型：`ChannelId` 与 `ThreadId` 不能互相赋值。
    /// 这一条在编译期由类型系统保证，测试只固定「它们确实是 newtype 而非 type alias」——
    /// 若有人把某个 ID 改成 `pub type ChannelId = String;`，下面这行会编译失败。
    #[test]
    fn ids_are_distinct_newtypes_not_aliases() {
        fn takes_channel(_: &ChannelId) {}
        let channel = ChannelId::new("c-1");
        takes_channel(&channel);
        assert_eq!(channel.as_ref(), "c-1");
    }
}
