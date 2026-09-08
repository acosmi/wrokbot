//! v2 record AEAD 的 AAD 绑定：[`RecordBinding`] 与它的**无歧义**编码。
//!
//! # v3 §6.4 逐字
//!
//! 「record AEAD 的 AAD 固定绑定 `tenant_id + secret_id + kind + owner + consumer +
//! key_version`。」
//!
//! AAD 的作用是让密文**不能被搬家**：把 A 租户某条模型密钥的密文整段复制到 B 租户另一条
//! 记录的行里，解密必须失败。v1 信封没有 AAD（实测：上游 `encryptSecret` 调
//! `crypto.subtle.encrypt({name:"AES-GCM", iv}, …)`，第一个参数里没有 `additionalData`
//! 字段），所以上游那份密文是可以随便搬的 —— 这正是 v2 要关掉的洞。
//!
//! # 为什么编码必须是长度前缀而不是分隔符拼接
//!
//! 拼接会撞车：`tenant="a", secret="b"` 与 `tenant="a|b", secret=""` 在任何分隔符方案下都能
//! 拼出同一串字节（把分隔符本身塞进字段里就行）。撞车意味着**两条不同记录共享同一个 AAD**，
//! 于是密文可以在这两条记录之间搬家 —— AAD 就白绑了。
//!
//! 本模块用 `u64` 大端长度前缀（[`push_framed`]）：每个字段写成 `len(8B) || bytes`。这个编码
//! 是单射的，理由是解码是确定性的（读 8 字节长度，再读那么多字节，重复六次），因此不可能有
//! 两组不同的输入映射到同一串输出。
//!
//! 长度前缀用 `u64` 而不是 `u32`，是为了让编码函数**无失败路径**：`u32` 需要一次
//! `usize -> u32` 的转换，而那次转换在超长输入下要么 panic 要么截断，截断恰好就是"两组
//! 不同输入撞出同一串字节"的重新引入。多花 4 字节换掉一整条 `Result`，划算。
//!
//! # 为什么 `key_version` 也进 AAD
//!
//! 进 AAD 意味着**换了 KEK 版本之后，旧密文用新版本的 binding 解不开**。这是要的：
//!
//! - 它把"这条密文属于哪一代密钥"从一个可以被改写的 JSON 字段，变成了密文自身完整性的一部分。
//!   否则攻击者只要把行里的 `key_version` 改成一个已泄漏的旧版本，就能诱导我们用弱密钥去解。
//! - 它让 KEK 轮换成为一次**可验收**的迁移：没有被重新封装的记录会当场报
//!   [`super::VaultError::Decrypt`]，而不是继续静默地用旧密钥工作到某天没人记得为止。
//!
//! 代价是轮换 KEK 必须走一遍与 v1→v2 相同的迁移流程（[`super::rotation`]）。这个代价是
//! 设计意图，不是遗漏。

use openbot_contracts::ids::{ActorId, BotId, TenantId};

/// AAD 的域分隔前缀：record 载荷。
///
/// 与 [`AAD_PREFIX_DATA_KEY`] 不同，于是一段**包装 DEK 的密文**永远不可能被当作 record 密文
/// 解开，反之亦然。没有域分隔的话，两处用同一把 KEK、同一个六元组，密文可以互换位置。
const AAD_PREFIX_RECORD: &[u8] = b"openbot.vault.aad.record.v1\x00";

/// AAD 的域分隔前缀：包装 DEK 的载荷。
const AAD_PREFIX_DATA_KEY: &[u8] = b"openbot.vault.aad.datakey.v1\x00";

/// 进 AAD 的字段数。写进编码本身，好让"以后有人加了第七个字段"变成一次可检出的不匹配，
/// 而不是一段能被旧代码正常解开的字节。
const AAD_FIELD_COUNT: u64 = 6;

/// KEK / master key 的版本号。
///
/// 用 `u32` 而不是字符串：与 `openbot_contracts::ids` 里两个 generation 计数器同一条理由 ——
/// 它是本系统自己铸造的单调计数器，没有上游既有取值需要兼容，而且"这是不是更新的一代"
/// 依赖**数值序**，字符串的字典序会判 `"10" < "9"`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// 由原始版本号构造。
    #[must_use]
    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    /// 取出原始版本号。
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// vault 里一条 secret 的标识。
///
/// # 为什么它在 vault 里而不在 `openbot-contracts::ids`
///
/// D-2 复算时它的全部消费者都在 `openbot-domain::vault`，没有第一条真实跨层契约。W-7b/R59
/// 之后 infra adapter 会在调用本模块的 `RecordBinding` 时**就地构造**它；这仍是 adapter 使用
/// domain value，不是 application/transport port 传递的 contract。若未来它第一次穿过 port，
/// 必须与那条用例同批上收，而不是因为 infra 调一次领域纯函数就把领域值全部搬进 contracts。
/// 语义上它与 §5.3 的 string newtype 一致：**不做 UUID 校验**，因为上游
/// `credentials.id` 是 `uuid defaultRandom`，而兼容端必须接受上游既有字符串。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretId(String);

impl SecretId {
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
}

/// 外部服务的登记标识（MCP server、vendor gateway 之类）。
///
/// 与 [`SecretId`] 同理不穿 application/transport port，因此不在 contracts。它**不是**一个 §5.3 核心 ID，只是
/// [`SecretPrincipal::Service`] 用来指名道姓的那串字符 —— 不给它一个类型的话，AAD 里就会出现
/// 一个裸 `String` 字段，而裸字符串正是撞车的来源。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceId(String);

impl ServiceId {
    /// 由任意可转 `String` 的值构造。
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

/// 上游 `credential_kind` 的六个变体。
///
/// **parity**：取值逐字对齐 `server/src/db/schema/core.ts::credentialKind` 在
/// `891df72f1827454d8b353d108fe5dd2313b7e30d` 的枚举（复算命令记在 `parity/tables.yaml`
/// 的 `tbl-credentials` notes 里，答案是 6）。这不是"我们觉得应该有哪几种"，改它等于改
/// 数据库的 check constraint。
///
/// # 它与 [`super::SecretClass`] 的分工
///
/// `SecretKind` 是**存储层**的分类（哪张表、哪个 check constraint、`kind` 列填什么），
/// `SecretClass` 是 §6.4 的**外泄风险**分类。两者不是一一对应：`kind = 'mcp'` 的一行可能
/// 装的是 access token 也可能是 refresh token，而只有后者落在 §6.4 的清单里。合并它们会
/// 让其中一边被另一边的取值范围绑架。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKind {
    /// `model` —— 模型供应商密钥。
    Model,
    /// `connector` —— 第一方 connector 的凭据。
    Connector,
    /// `agent` —— 客户自带 Agent 背后的密钥（上游注释：「Its own kind so "what does this
    /// deployment hold" stays true.」）。
    Agent,
    /// `mcp` —— 某个 MCP server 的 token。
    Mcp,
    /// `mcp_oauth_client` —— **部署**向 vendor 登记的 OAuth client。
    ///
    /// 与 [`Self::McpUserToken`] 刻意分开，上游注释逐字：「A client identifies this deployment
    /// to a vendor and can read nobody's data on its own」。
    McpOauthClient,
    /// `mcp_user_token` —— **个人**的 MCP 授权。
    McpUserToken,
}

impl SecretKind {
    /// 全部六个变体，顺序与上游 `pgEnum` 的声明顺序一致。
    pub const ALL: [Self; 6] = [
        Self::Model,
        Self::Connector,
        Self::Agent,
        Self::Mcp,
        Self::McpOauthClient,
        Self::McpUserToken,
    ];

    /// 数据库里那个字面量。**改它 = 改 check constraint**，见类型文档。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Connector => "connector",
            Self::Agent => "agent",
            Self::Mcp => "mcp",
            Self::McpOauthClient => "mcp_oauth_client",
            Self::McpUserToken => "mcp_user_token",
        }
    }
}

/// AAD 里 `owner` / `consumer` 两个槽位的取值。
///
/// # owner 与 consumer 为什么是两个槽而不是一个
///
/// 它们回答两个不同的问题：**owner** 是"这条 secret 属于谁"（谁被撤权它就该失效，
/// §6.5 条 6：「IdP 撤组后递增 auth generation 并撤销相应 membership」），**consumer** 是
/// "谁被允许拿它去解密"。个人 MCP 授权（`mcp_user_token`）就是两者不同的典型：owner 是那个人，
/// consumer 是那台 MCP server。绑成一个槽，就没法表达"这个人的 token 只能给这台 server 用"。
///
/// # 为什么是封闭枚举
///
/// 一个自由字符串会把整条 AAD 的强度压回到"调用方记得拼对"。封闭枚举加上
/// [`SecretPrincipal::encode`] 的两段式编码（标签 + 主体，各自长度前缀），让
/// `Actor("x")` 与 `Service("x")` 在字节层面必然不同。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretPrincipal {
    /// 整个部署。deployment 级凭据（模型密钥、updater key）的 owner。
    Deployment,
    /// 某个自然人。
    Actor(ActorId),
    /// 某个 Bot。
    Bot(BotId),
    /// 某个已登记的外部服务（MCP server、vendor gateway）。
    Service(ServiceId),
}

impl SecretPrincipal {
    /// 变体标签。进 AAD 的第一段。
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Actor(_) => "actor",
            Self::Bot(_) => "bot",
            Self::Service(_) => "service",
        }
    }

    /// 主体标识。进 AAD 的第二段；[`Self::Deployment`] 没有主体，写空串。
    ///
    /// 空串不会与"主体恰好是空串的 actor"撞车 —— 标签段先不同（`deployment` vs `actor`）。
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            Self::Deployment => "",
            Self::Actor(id) => id.as_str(),
            Self::Bot(id) => id.as_str(),
            Self::Service(id) => id.as_str(),
        }
    }

    /// 编成一段自描述字节：`framed(tag) || framed(subject)`。
    ///
    /// 它本身还会被外层再包一次长度前缀（见 [`RecordBinding::encode`]），所以 principal 整体
    /// 只占 AAD 六个槽里的**一个** —— 与 §6.4 那句"六项"逐字对得上。
    #[must_use]
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_framed(&mut out, self.tag().as_bytes());
        push_framed(&mut out, self.subject().as_bytes());
        out
    }
}

/// 写入一个长度前缀字段：`u64 大端长度 || 内容`。
///
/// 单射性的全部理由见模块文档。
fn push_framed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// v3 §6.4 那六项的类型化表达，以及它们到 AAD 字节的唯一编码。
///
/// 字段私有 + 构造器：公开字段意味着任何人都能在构造之后把 `key_version` 改掉，而
/// [`super::aead::open_v2`] 依赖"binding 里的 key_version 是调用方的权威判断"这条前提。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordBinding {
    tenant: TenantId,
    secret_id: SecretId,
    kind: SecretKind,
    owner: SecretPrincipal,
    consumer: SecretPrincipal,
    key_version: KeyVersion,
}

impl RecordBinding {
    /// 构造一次绑定。六个参数的顺序与 §6.4 原文的列举顺序一致。
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        secret_id: SecretId,
        kind: SecretKind,
        owner: SecretPrincipal,
        consumer: SecretPrincipal,
        key_version: KeyVersion,
    ) -> Self {
        Self {
            tenant,
            secret_id,
            kind,
            owner,
            consumer,
            key_version,
        }
    }

    /// 这条绑定属于哪个租户。
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// 被绑定的 secret。
    #[must_use]
    pub const fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    /// 存储层分类。
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    /// 属于谁。
    #[must_use]
    pub const fn owner(&self) -> &SecretPrincipal {
        &self.owner
    }

    /// 谁可以用。
    #[must_use]
    pub const fn consumer(&self) -> &SecretPrincipal {
        &self.consumer
    }

    /// 用哪一代 KEK 封装。
    ///
    /// **这是权威值**：[`super::aead::open_v2`] 拿它与信封自述的版本比对，不一致即拒
    /// （[`super::VaultError::KeyVersionMismatch`]）。密文不许自述身份。
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    /// 换一个 KEK 版本，其余五项不变。
    ///
    /// KEK 轮换时要用：同一条记录、同一个 owner / consumer，只是换代封装。做成方法而不是让
    /// 字段公开，是因为"只允许改这一项"本身就是想表达的约束。
    #[must_use]
    pub fn with_key_version(&self, key_version: KeyVersion) -> Self {
        Self {
            key_version,
            ..self.clone()
        }
    }

    /// record 载荷的 AAD 字节。
    #[must_use]
    pub fn record_aad(&self) -> Vec<u8> {
        self.encode(AAD_PREFIX_RECORD)
    }

    /// 包装 DEK 时的 AAD 字节。
    ///
    /// 与 [`Self::record_aad`] 只差域分隔前缀，理由见 [`AAD_PREFIX_RECORD`]。
    #[must_use]
    pub fn data_key_aad(&self) -> Vec<u8> {
        self.encode(AAD_PREFIX_DATA_KEY)
    }

    /// 两种 AAD 共用的编码骨架。
    fn encode(&self, prefix: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(prefix);
        out.extend_from_slice(&AAD_FIELD_COUNT.to_be_bytes());
        push_framed(&mut out, self.tenant.as_str().as_bytes());
        push_framed(&mut out, self.secret_id.as_str().as_bytes());
        push_framed(&mut out, self.kind.as_str().as_bytes());
        push_framed(&mut out, &self.owner.encode());
        push_framed(&mut out, &self.consumer.encode());
        push_framed(&mut out, &self.key_version.get().to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(tenant: &str, secret: &str) -> RecordBinding {
        RecordBinding::new(
            TenantId::new(tenant),
            SecretId::new(secret),
            SecretKind::Model,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new("gateway")),
            KeyVersion::new(1),
        )
    }

    /// 模块文档点名的那对撞车候选：分隔符方案下它们会拼出同一串字节。
    #[test]
    fn separator_collision_candidates_encode_differently() {
        let left = binding("a", "b");
        let right = binding("a|b", "");
        assert_ne!(left.record_aad(), right.record_aad());

        // 换几个常见分隔符再来一次 —— 单射性不该依赖"我们没想到那个分隔符"。
        // 这些二元组两两不同，所以它们的 AAD 也必须两两不同。
        let probes = [
            ("a", "b"),
            ("ab", ""),
            ("", "ab"),
            ("a\u{0}b", ""),
            ("", "a\u{0}b"),
            ("a:b", ""),
            ("a", ":b"),
            ("a/b", ""),
            ("a", "/b"),
        ];
        let mut encoded: Vec<Vec<u8>> = probes
            .iter()
            .map(|(tenant, secret)| binding(tenant, secret).record_aad())
            .collect();
        let total = encoded.len();
        encoded.sort_unstable();
        encoded.dedup();
        assert_eq!(
            encoded.len(),
            total,
            "两组不同的 (tenant, secret) 撞出了同一个 AAD"
        );

        // 正向对照：编码是确定性的，否则上面的"两两不同"在"编码里掺了随机数"的世界里也成立。
        assert_eq!(
            binding("a", "b").record_aad(),
            binding("a", "b").record_aad()
        );
    }

    /// 一组两两不同的 binding 必须给出两两不同的 AAD。
    ///
    /// 这是单射性的机械核对：每个字段各变一次，外加那对分隔符撞车候选。
    #[test]
    fn distinct_bindings_produce_distinct_aad() {
        let base = RecordBinding::new(
            TenantId::new("tenant-1"),
            SecretId::new("secret-1"),
            SecretKind::Model,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new("svc-1")),
            KeyVersion::new(1),
        );

        let variants = [
            base.clone(),
            RecordBinding::new(
                TenantId::new("tenant-2"),
                SecretId::new("secret-1"),
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(1),
            ),
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-2"),
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(1),
            ),
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-1"),
                SecretKind::Mcp,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(1),
            ),
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-1"),
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("svc-1")),
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(1),
            ),
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-1"),
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Bot(BotId::new("svc-1")),
                KeyVersion::new(1),
            ),
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-1"),
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(2),
            ),
            // 「同一个 id 换个 principal 变体」—— 标签段必须把它们分开。
            RecordBinding::new(
                TenantId::new("tenant-1"),
                SecretId::new("secret-1"),
                SecretKind::Model,
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                SecretPrincipal::Service(ServiceId::new("svc-1")),
                KeyVersion::new(1),
            ),
        ];

        let mut encoded: Vec<Vec<u8>> = variants.iter().map(RecordBinding::record_aad).collect();
        let total = encoded.len();
        encoded.sort_unstable();
        encoded.dedup();
        assert_eq!(encoded.len(), total, "两条不同的 binding 撞出了同一个 AAD");

        // 正向对照：同一个 binding 两次编码必须相等，否则上面的"两两不同"在
        // "编码里掺了随机数"的世界里同样通过。
        assert_eq!(base.record_aad(), base.clone().record_aad());
    }

    /// record 与 DEK 两种 AAD 必须不同 —— 否则两处密文可以互换位置。
    #[test]
    fn record_and_data_key_aad_are_domain_separated() {
        let binding = binding("tenant-1", "secret-1");
        assert_ne!(binding.record_aad(), binding.data_key_aad());

        // 正向对照：两者确实共享同一个六元组尾巴，只有前缀不同。
        let record = binding.record_aad();
        let data_key = binding.data_key_aad();
        assert_eq!(
            record[AAD_PREFIX_RECORD.len()..],
            data_key[AAD_PREFIX_DATA_KEY.len()..]
        );
    }

    /// `with_key_version` 只改一项。
    #[test]
    fn with_key_version_changes_only_the_version() {
        let base = binding("tenant-1", "secret-1");
        let rotated = base.with_key_version(KeyVersion::new(9));

        assert_eq!(rotated.key_version(), KeyVersion::new(9));
        assert_eq!(rotated.tenant(), base.tenant());
        assert_eq!(rotated.secret_id(), base.secret_id());
        assert_eq!(rotated.kind(), base.kind());
        assert_eq!(rotated.owner(), base.owner());
        assert_eq!(rotated.consumer(), base.consumer());
        assert_ne!(rotated.record_aad(), base.record_aad());
    }

    /// 六个 `SecretKind` 的字面量与上游 `pgEnum` 逐字相同，且两两不同。
    #[test]
    fn secret_kind_labels_match_the_upstream_enum() {
        assert_eq!(
            SecretKind::ALL.map(SecretKind::as_str).to_vec(),
            vec![
                "model",
                "connector",
                "agent",
                "mcp",
                "mcp_oauth_client",
                "mcp_user_token"
            ],
            "取值与顺序对齐 server/src/db/schema/core.ts::credentialKind @891df72f18"
        );
        let mut labels = SecretKind::ALL.map(SecretKind::as_str).to_vec();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), 6);
    }

    /// AAD 里写着字段数。改成七项而忘了同步这个常量，编码会当场不同。
    #[test]
    fn aad_declares_its_field_count() {
        let binding = binding("t", "s");
        let aad = binding.record_aad();
        let start = AAD_PREFIX_RECORD.len();
        let count = u64::from_be_bytes(
            aad[start..start + 8]
                .try_into()
                .expect("AAD 前缀之后必然有 8 字节字段数"),
        );
        assert_eq!(count, 6, "§6.4 逐字六项");
    }
}
