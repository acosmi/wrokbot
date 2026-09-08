//! PNG visual-golden verification owned by the developer-only xtask binary.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use image::{ColorType, ImageEncoder as _, ImageFormat, ImageReader, Limits};
use openbot_testkit::golden::{
    CHANNEL_DIFFERENCE_THRESHOLD, GoldenComparison, MaskRect, RgbaImage, compare_rgba,
};
use serde::Deserialize;
use walkdir::WalkDir;

const DEFAULT_MANIFEST: &str = "fixtures/ui/golden/MANIFEST.toml";
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_PNG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 4_096;
const MAX_IMAGE_ALLOCATION: u64 = 64 * 1024 * 1024;
const MAX_RESOLVED_MASKS: usize = 64;
const EXPECTED_TOTAL: usize = 245;
const EXPECTED_COUNTS: [(&str, usize); 3] =
    [("web", 137), ("macos-arm64", 54), ("windows-x64", 54)];
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "check-manifest" => {
            if args.len() != 1 {
                return usage();
            }
            let manifest = workspace.join(DEFAULT_MANIFEST);
            let rules = ManifestRules::load(&manifest)?;
            println!(
                "golden manifest: ok (matrix={EXPECTED_TOTAL}; masks={}; ready={})",
                rules.allowed_masks.len(),
                rules.ready
            );
            Ok(())
        }
        "compare" => compare_command(workspace, &args[1..]),
        "verify" => verify_command(workspace, &args[1..]),
        _ => usage(),
    }
}

fn usage<T>() -> Result<T> {
    bail!(
        "usage: cargo xtask golden check-manifest | compare --expected PNG --actual PNG [--masks JSON] | verify --actual-root DIR"
    )
}

fn compare_command(workspace: &Path, args: &[String]) -> Result<()> {
    let parsed = CompareArgs::parse(workspace, args)?;
    let rules = ManifestRules::load(&workspace.join(DEFAULT_MANIFEST))?;
    let masks = match parsed.masks {
        Some(path) => {
            let image = parsed
                .expected
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow!("golden expected file name is not UTF-8"))?;
            load_masks(&path, Some(image), &rules)?
        }
        None => Vec::new(),
    };
    let file_name = parsed
        .expected
        .file_name()
        .ok_or_else(|| anyhow!("golden expected PNG has no file name"))?;
    let mut diff_name = OsString::from(file_name);
    diff_name.push(".diff.png");
    let diff = rules.diff_root.join("single").join(diff_name);
    rules.validate_diff_path(&diff)?;
    let result = compare_pair(&parsed.expected, &parsed.actual, &masks, Some(&diff))?;
    print_result(&result);
    if result.comparison.is_match() {
        Ok(())
    } else {
        bail!("golden comparison failed; diff={}", diff.display())
    }
}

fn verify_command(workspace: &Path, args: &[String]) -> Result<()> {
    let parsed = VerifyArgs::parse(workspace, args)?;
    let rules = ManifestRules::load(&workspace.join(DEFAULT_MANIFEST))?;
    rules.require_ready()?;
    let actual_root = parsed
        .actual_root
        .canonicalize()
        .context("golden actual root is unavailable")?;
    let baseline_root = rules
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("golden manifest has no parent"))?
        .canonicalize()
        .context("golden baseline root is unavailable")?;
    if actual_root == baseline_root || actual_root.starts_with(&baseline_root) {
        bail!("golden actual root must be outside the immutable baseline root");
    }

    let baseline = collect_matrix_pngs(&baseline_root, &rules.expected_paths)?;
    let actual = collect_pngs(&actual_root)?;
    let baseline_keys = baseline.keys().cloned().collect::<BTreeSet<_>>();
    let actual_keys = actual.keys().cloned().collect::<BTreeSet<_>>();
    if baseline_keys != actual_keys {
        let missing = baseline_keys.difference(&actual_keys).collect::<Vec<_>>();
        let extra = actual_keys.difference(&baseline_keys).collect::<Vec<_>>();
        bail!(
            "golden file inventory mismatch: missing={}; extra={}",
            missing.len(),
            extra.len()
        );
    }

    let mut failures = 0_usize;
    let mut compared = 0_usize;
    for (relative, expected) in baseline {
        let actual = actual
            .get(&relative)
            .ok_or_else(|| anyhow!("golden actual inventory changed during verification"))?;
        let mask_path = append_suffix(actual, ".masks.json");
        let masks = if mask_path.is_file() {
            let relative = slash_path(&relative)?;
            load_masks(&mask_path, Some(&relative), &rules)?
        } else {
            Vec::new()
        };
        let diff = rules.diff_root.join(&relative);
        rules.validate_diff_path(&diff)?;
        let result = compare_pair(&expected, actual, &masks, Some(&diff))?;
        let (required_width, required_height) = dimensions_from_name(&relative)?;
        if result.width != required_width || result.height != required_height {
            bail!("golden PNG dimensions disagree with its closed matrix file name");
        }
        compared = compared
            .checked_add(1)
            .ok_or_else(|| anyhow!("golden comparison count overflow"))?;
        if !result.comparison.is_match() {
            failures = failures
                .checked_add(1)
                .ok_or_else(|| anyhow!("golden failure count overflow"))?;
        }
    }
    if compared != EXPECTED_TOTAL {
        bail!("golden compared {compared} PNGs, expected {EXPECTED_TOTAL}");
    }
    if failures != 0 {
        bail!(
            "golden verify failed: {failures}/{compared} images differ; diffs={} ",
            rules.diff_root.display()
        );
    }
    println!("golden verify: ok ({compared} PNGs; failures=0)");
    Ok(())
}

fn print_result(result: &PairResult) {
    println!(
        "golden compare: match={} dimensions={}x{} comparable={} different={} ratio_exceeded={} full_8x8={}",
        result.comparison.is_match(),
        result.width,
        result.height,
        result.comparison.comparable_pixels(),
        result.comparison.different_pixels(),
        result.comparison.difference_ratio_exceeded(),
        result.comparison.has_full_difference_block(),
    );
}

struct CompareArgs {
    expected: PathBuf,
    actual: PathBuf,
    masks: Option<PathBuf>,
}

impl CompareArgs {
    fn parse(workspace: &Path, args: &[String]) -> Result<Self> {
        let mut expected = None;
        let mut actual = None;
        let mut masks = None;
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow!("{flag} requires a value"))?;
            let slot = match flag {
                "--expected" => &mut expected,
                "--actual" => &mut actual,
                "--masks" => &mut masks,
                _ => return usage(),
            };
            if slot.replace(resolve(workspace, value)).is_some() {
                bail!("duplicate golden argument {flag}");
            }
            index += 2;
        }
        Ok(Self {
            expected: expected.ok_or_else(|| anyhow!("golden compare requires --expected"))?,
            actual: actual.ok_or_else(|| anyhow!("golden compare requires --actual"))?,
            masks,
        })
    }
}

struct VerifyArgs {
    actual_root: PathBuf,
}

impl VerifyArgs {
    fn parse(workspace: &Path, args: &[String]) -> Result<Self> {
        let mut actual_root = None;
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow!("{flag} requires a value"))?;
            let slot = match flag {
                "--actual-root" => &mut actual_root,
                _ => return usage(),
            };
            if slot.replace(resolve(workspace, value)).is_some() {
                bail!("duplicate golden argument {flag}");
            }
            index += 2;
        }
        Ok(Self {
            actual_root: actual_root
                .ok_or_else(|| anyhow!("golden verify requires --actual-root"))?,
        })
    }
}

fn resolve(workspace: &Path, value: &str) -> PathBuf {
    let value = PathBuf::from(value);
    if value.is_absolute() {
        value
    } else {
        workspace.join(value)
    }
}

struct ManifestRules {
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    diff_root: PathBuf,
    allowed_masks: BTreeMap<String, BTreeSet<String>>,
    expected_paths: BTreeSet<PathBuf>,
    ready: bool,
}

impl ManifestRules {
    fn load(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).context("golden manifest is unavailable")?;
        if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
            bail!("golden manifest size is outside the closed limit");
        }
        let source = fs::read_to_string(path).context("golden manifest is not UTF-8")?;
        let value =
            toml::from_str::<toml::Value>(&source).context("golden manifest is malformed TOML")?;
        require_str(&value, &["schema"], "ui-golden-manifest")?;
        require_integer(&value, &["schema_version"], 2)?;
        require_integer(&value, &["compare", "channel_threshold"], 16)?;
        require_integer(&value, &["compare", "block_size"], 8)?;
        require_float(&value, &["compare", "diff_pixel_ratio_max"], 0.001)?;
        require_integer(&value, &["matrix_totals", "grand_total"], 245)?;
        validate_matrices(&value)?;
        validate_budgets(&value)?;
        let allowed_masks = validate_masks(&value)?;
        validate_naming(&value)?;

        let diff_relative = get(&value, &["compare", "update_flow", "diff_dir"])?
            .as_str()
            .ok_or_else(|| anyhow!("golden diff_dir must be a string"))?;
        if diff_relative != "fixtures/ui/golden/_diff/" {
            bail!("golden diff_dir drifted from the ignored review-artifact directory");
        }
        let workspace = path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| anyhow!("golden manifest is outside the repository layout"))?;
        let workspace_root = workspace
            .canonicalize()
            .context("golden workspace root is unavailable")?;
        validate_image_dependency(&workspace_root)?;
        let diff_root = workspace_root.join(diff_relative);
        let expected_paths = expected_inventory(&workspace_root)?;
        if expected_paths.len() != EXPECTED_TOTAL {
            bail!("golden derived file inventory is not {EXPECTED_TOTAL}");
        }

        let digest = get(&value, &["image", "digest"])?
            .as_str()
            .ok_or_else(|| anyhow!("golden image digest must be a string"))?;
        let digest_status = get(&value, &["image", "digest_status"])?
            .as_str()
            .ok_or_else(|| anyhow!("golden image digest status must be a string"))?;
        let cjk = get(&value, &["image", "cjk_font_package_version"])?
            .as_str()
            .ok_or_else(|| anyhow!("golden CJK package version must be a string"))?;
        let ready = digest_status == "fixed"
            && valid_sha256_digest(digest)
            && !cjk.is_empty()
            && cjk != "TBD";

        Ok(Self {
            manifest_path: path.to_path_buf(),
            workspace_root,
            diff_root,
            allowed_masks,
            expected_paths,
            ready,
        })
    }

    fn require_ready(&self) -> Result<()> {
        if !self.ready {
            bail!(
                "golden manifest is structurally valid but container/font provenance is not fixed"
            );
        }
        Ok(())
    }

    fn validate_diff_path(&self, path: &Path) -> Result<()> {
        if !path.starts_with(&self.diff_root) || !path.starts_with(&self.workspace_root) {
            bail!("golden diff path escaped the ignored review-artifact root");
        }
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("golden diff path has no parent"))?;
        let relative = parent
            .strip_prefix(&self.workspace_root)
            .map_err(|_| anyhow!("golden diff parent escaped the workspace"))?;
        let mut current = self.workspace_root.clone();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    bail!("golden diff path contains a symlink or non-directory ancestor");
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error).context("golden diff path cannot be inspected"),
            }
        }
        Ok(())
    }
}

fn validate_image_dependency(workspace: &Path) -> Result<()> {
    let root = toml::from_str::<toml::Value>(&fs::read_to_string(workspace.join("Cargo.toml"))?)?;
    let image = get(&root, &["workspace", "dependencies", "image"])?
        .as_table()
        .ok_or_else(|| anyhow!("workspace image dependency must be a closed table"))?;
    if image.get("version").and_then(toml::Value::as_str) != Some("=0.25.10")
        || image.get("default-features").and_then(toml::Value::as_bool) != Some(false)
        || image
            .get("features")
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            != Some(vec!["png"])
    {
        bail!("workspace image dependency drifted from exact PNG-only 0.25.10");
    }

    let testkit_path = workspace.join("crates/openbot-testkit/Cargo.toml");
    let testkit = toml::from_str::<toml::Value>(&fs::read_to_string(testkit_path)?)?;
    let direct = get(&testkit, &["dependencies", "image"])?
        .as_table()
        .ok_or_else(|| anyhow!("testkit image dependency must be a closed table"))?;
    if direct.get("workspace").and_then(toml::Value::as_bool) != Some(true)
        || direct.get("optional").and_then(toml::Value::as_bool) != Some(true)
    {
        bail!("image must remain an optional testkit-only dependency");
    }
    let xtask = get(&testkit, &["features", "xtask"])?
        .as_array()
        .ok_or_else(|| anyhow!("testkit xtask feature is malformed"))?;
    if xtask
        .iter()
        .filter_map(toml::Value::as_str)
        .filter(|value| *value == "dep:image")
        .count()
        != 1
    {
        bail!("image must be enabled exactly once by the xtask feature");
    }

    for entry in fs::read_dir(workspace.join("crates"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entry.file_name() == "openbot-testkit" {
            continue;
        }
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let value = toml::from_str::<toml::Value>(&fs::read_to_string(&manifest)?)?;
        if manifest_uses_dependency(&value, "image") {
            bail!("image dependency escaped openbot-testkit into a product crate");
        }
    }

    let lock = toml::from_str::<toml::Value>(&fs::read_to_string(workspace.join("Cargo.lock"))?)?;
    let packages = get(&lock, &["package"])?
        .as_array()
        .ok_or_else(|| anyhow!("Cargo.lock package array is missing"))?;
    let image_packages = packages
        .iter()
        .filter_map(toml::Value::as_table)
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("image"))
        .collect::<Vec<_>>();
    if image_packages.len() != 1
        || image_packages[0]
            .get("version")
            .and_then(toml::Value::as_str)
            != Some("0.25.10")
        || image_packages[0]
            .get("checksum")
            .and_then(toml::Value::as_str)
            != Some("85ab80394333c02fe689eaf900ab500fbd0c2213da414687ebf995a65d5a6104")
    {
        bail!("Cargo.lock image identity/checksum drifted");
    }
    Ok(())
}

fn manifest_uses_dependency(value: &toml::Value, dependency: &str) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    table.iter().any(|(key, child)| {
        (matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) && child.get(dependency).is_some())
            || manifest_uses_dependency(child, dependency)
    })
}

fn validate_naming(value: &toml::Value) -> Result<()> {
    require_str(value, &["naming", "root_page_key"], "home")?;
    require_str(value, &["naming", "route_segment_separator"], "--")?;
    require_str(value, &["naming", "gallery_page_key"], "design-gallery")?;
    require_str(value, &["naming", "gallery_viewport"], "1440x900")?;
    Ok(())
}

#[derive(Deserialize)]
struct GoldenSeed {
    #[serde(default)]
    pages_covered: Vec<GoldenSeedPage>,
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenSeedPage {
    route: String,
    upstream: String,
    label: String,
    seed_keys: Vec<String>,
    auth: String,
    #[serde(default)]
    golden_param: BTreeMap<String, String>,
    #[serde(default)]
    note: Option<String>,
}

fn expected_inventory(workspace: &Path) -> Result<BTreeSet<PathBuf>> {
    let seed_path = workspace.join("fixtures/ui/seed.json");
    let seed = serde_json::from_slice::<GoldenSeed>(&fs::read(seed_path)?)
        .context("golden seed inventory is malformed")?;
    if seed.pages_covered.len() != 27 || seed.other.is_empty() {
        bail!("golden seed must contain 27 pages and the fixed data corpus");
    }
    let mut pages = BTreeSet::new();
    for page in seed.pages_covered {
        if page.upstream.is_empty()
            || page.label.is_empty()
            || page.seed_keys.is_empty()
            || !matches!(page.auth.as_str(), "admin" | "signed-out")
            || page.note.as_ref().is_some_and(|note| note.len() > 4_096)
        {
            bail!("golden seed page metadata is incomplete");
        }
        let key = page_key(&page.route, &page.golden_param)?;
        if !pages.insert(key) {
            bail!("golden page key collision");
        }
    }

    let mut output = BTreeSet::new();
    for page in &pages {
        for theme in ["light", "dark"] {
            for viewport in ["1440x900", "1024x640"] {
                output.insert(PathBuf::from("web").join(format!("{page}.{theme}.{viewport}.png")));
            }
            output
                .insert(PathBuf::from("macos-arm64").join(format!("{page}.{theme}.1440x900.png")));
            output
                .insert(PathBuf::from("windows-x64").join(format!("{page}.{theme}.1440x900.png")));
        }
        output.insert(PathBuf::from("web").join(format!("{page}.zh-CN.light.1440x900.png")));
    }
    for theme in ["light", "dark"] {
        output.insert(PathBuf::from("web").join(format!("design-gallery.{theme}.1440x900.png")));
    }
    Ok(output)
}

fn page_key(route: &str, parameters: &BTreeMap<String, String>) -> Result<String> {
    if route == "/" {
        if !parameters.is_empty() {
            bail!("golden root route must not carry parameters");
        }
        return Ok("home".to_owned());
    }
    if !route.starts_with('/') || route.ends_with('/') || route.contains("//") {
        bail!("golden route shape is invalid");
    }
    let mut used = BTreeSet::new();
    let mut segments = Vec::new();
    for segment in route.trim_start_matches('/').split('/') {
        let value = match segment.strip_prefix('$') {
            Some(parameter) => {
                let parameter = parameter.strip_suffix('_').unwrap_or(parameter);
                let value = parameters
                    .get(parameter)
                    .ok_or_else(|| anyhow!("golden route parameter is missing"))?;
                used.insert(parameter.to_owned());
                value.as_str()
            }
            None => segment,
        };
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("golden page-key segment is outside the closed ASCII set");
        }
        segments.push(value);
    }
    if used.len() != parameters.len() {
        bail!("golden page has unused route parameters");
    }
    Ok(segments.join("--"))
}

fn dimensions_from_name(relative: &Path) -> Result<(u32, u32)> {
    let stem = relative
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("golden PNG file name is not UTF-8"))?;
    let dimensions = stem
        .rsplit('.')
        .next()
        .ok_or_else(|| anyhow!("golden PNG file name has no dimensions"))?;
    match dimensions {
        "1440x900" => Ok((1_440, 900)),
        "1024x640" => Ok((1_024, 640)),
        _ => bail!("golden PNG file name has an unapproved viewport"),
    }
}

fn validate_matrices(value: &toml::Value) -> Result<()> {
    let matrices = get(value, &["matrix"])?
        .as_array()
        .ok_or_else(|| anyhow!("golden matrix must be an array"))?;
    let expected = BTreeMap::from([
        ("desktop-macos-arm64", 54_i64),
        ("desktop-windows-x64", 54_i64),
        ("web-en", 110_i64),
        ("web-zh-CN", 27_i64),
    ]);
    if matrices.len() != expected.len() {
        bail!("golden matrix must contain exactly four entries");
    }
    let mut actual = BTreeMap::new();
    for matrix in matrices {
        let table = matrix
            .as_table()
            .ok_or_else(|| anyhow!("golden matrix entry must be a table"))?;
        let id = table
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("golden matrix id is missing"))?;
        let count = table
            .get("count")
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| anyhow!("golden matrix count is missing"))?;
        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("golden matrix status is missing"))?;
        if !matches!(status, "todo" | "done") || actual.insert(id, count).is_some() {
            bail!("golden matrix id/status is outside the closed set");
        }
    }
    if actual != expected {
        bail!("golden matrix ids or counts drifted");
    }
    Ok(())
}

fn validate_budgets(value: &toml::Value) -> Result<()> {
    let budgets = get(value, &["budget"])?
        .as_array()
        .ok_or_else(|| anyhow!("golden budget must be an array"))?;
    let mut actual = BTreeMap::new();
    for budget in budgets {
        let table = budget
            .as_table()
            .ok_or_else(|| anyhow!("golden budget entry must be a table"))?;
        let artifact = table
            .get("artifact")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("golden budget artifact is missing"))?;
        let limit = table
            .get("limit_bytes")
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| anyhow!("golden budget limit is missing"))?;
        if actual.insert(artifact, limit).is_some() {
            bail!("golden budget artifact is duplicated");
        }
    }
    if actual
        != BTreeMap::from([
            ("app.css", 131_072_i64),
            ("app.wasm", 3_670_016_i64),
            ("fonts (两份 woff2)", 819_200_i64),
        ])
    {
        bail!("golden bundle budgets drifted from GUI v2 §10.5/R123");
    }
    let css = budgets
        .iter()
        .filter_map(toml::Value::as_table)
        .find(|table| table.get("artifact").and_then(toml::Value::as_str) == Some("app.css"))
        .ok_or_else(|| anyhow!("golden CSS budget is missing"))?;
    if css.get("warning_bytes").and_then(toml::Value::as_integer) != Some(122_880) {
        bail!("golden CSS warning must remain 120 KiB");
    }
    Ok(())
}

fn validate_masks(value: &toml::Value) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let masks = get(value, &["masks"])?
        .as_table()
        .ok_or_else(|| anyhow!("golden masks must be a table"))?;
    let count = masks
        .get("count")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| anyhow!("golden mask count is missing"))?;
    let allowed = masks
        .get("allowed")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| anyhow!("golden masks.allowed must be an array"))
        })
        .transpose()?
        .map_or(&[][..], Vec::as_slice);
    if usize::try_from(count).ok() != Some(allowed.len()) || allowed.len() > MAX_RESOLVED_MASKS {
        bail!("golden mask count does not match the reviewed allowlist");
    }
    let mut output = BTreeMap::new();
    for entry in allowed {
        let table = entry
            .as_table()
            .ok_or_else(|| anyhow!("golden mask allowlist entry must be a table"))?;
        let selector = table
            .get("selector")
            .and_then(toml::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256 && !value.contains('\0'))
            .ok_or_else(|| anyhow!("golden mask selector is invalid"))?;
        let pages = table
            .get("pages")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| anyhow!("golden mask pages are missing"))?;
        let pages = pages
            .iter()
            .map(|page| {
                page.as_str()
                    .filter(|page| page.starts_with('/') && page.len() <= 256)
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("golden mask page is invalid"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if pages.is_empty() || output.insert(selector.to_owned(), pages).is_some() {
            bail!("golden mask selector/pages are empty or duplicated");
        }
        for required in ["why", "approved_in_pr"] {
            if table
                .get(required)
                .and_then(toml::Value::as_str)
                .is_none_or(str::is_empty)
            {
                bail!("golden mask review evidence is incomplete");
            }
        }
    }
    Ok(output)
}

fn get<'a>(value: &'a toml::Value, path: &[&str]) -> Result<&'a toml::Value> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or_else(|| anyhow!("golden manifest is missing {}", path.join(".")))?;
    }
    Ok(current)
}

fn require_str(value: &toml::Value, path: &[&str], expected: &str) -> Result<()> {
    if get(value, path)?.as_str() != Some(expected) {
        bail!("golden manifest {} drifted", path.join("."));
    }
    Ok(())
}

fn require_integer(value: &toml::Value, path: &[&str], expected: i64) -> Result<()> {
    if get(value, path)?.as_integer() != Some(expected) {
        bail!("golden manifest {} drifted", path.join("."));
    }
    Ok(())
}

fn require_float(value: &toml::Value, path: &[&str], expected: f64) -> Result<()> {
    if get(value, path)?.as_float() != Some(expected) {
        bail!("golden manifest {} drifted", path.join("."));
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaskDocument {
    schema: String,
    image: String,
    page: String,
    rectangles: Vec<ResolvedMask>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedMask {
    selector: String,
    x: u64,
    y: u64,
    width: u64,
    height: u64,
}

fn load_masks(
    path: &Path,
    image_binding: Option<&str>,
    rules: &ManifestRules,
) -> Result<Vec<MaskRect>> {
    let metadata = fs::metadata(path).context("golden mask sidecar is unavailable")?;
    if metadata.len() == 0 || metadata.len() > 64 * 1024 {
        bail!("golden mask sidecar size is outside the closed limit");
    }
    let document = serde_json::from_slice::<MaskDocument>(&fs::read(path)?)
        .context("golden mask sidecar is malformed")?;
    if document.schema != "openbot-golden-mask-resolution-v1"
        || document.rectangles.is_empty()
        || document.rectangles.len() > MAX_RESOLVED_MASKS
        || document.page.len() > 256
        || !document.page.starts_with('/')
    {
        bail!("golden mask sidecar shape is outside the closed contract");
    }
    if let Some(image_binding) = image_binding
        && document.image != image_binding
    {
        bail!("golden mask sidecar is bound to another image");
    }
    document
        .rectangles
        .into_iter()
        .map(|mask| {
            let pages = rules
                .allowed_masks
                .get(&mask.selector)
                .ok_or_else(|| anyhow!("golden mask selector is not in the reviewed manifest"))?;
            if !pages.contains(&document.page) {
                bail!("golden mask selector is not approved for this page");
            }
            Ok(MaskRect {
                x: usize::try_from(mask.x)?,
                y: usize::try_from(mask.y)?,
                width: usize::try_from(mask.width)?,
                height: usize::try_from(mask.height)?,
            })
        })
        .collect()
}

fn slash_path(path: &Path) -> Result<String> {
    let mut output = String::new();
    for component in path.components() {
        let value = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow!("golden relative path is not UTF-8"))?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(value);
    }
    Ok(output)
}

struct DecodedPng {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

fn decode_png(path: &Path) -> Result<DecodedPng> {
    if path.extension().and_then(|value| value.to_str()) != Some("png") {
        bail!("golden input file name must end in lowercase .png");
    }
    let metadata = fs::metadata(path).context("golden PNG is unavailable")?;
    if metadata.len() == 0 || metadata.len() > MAX_PNG_BYTES {
        bail!("golden PNG size is outside the closed limit");
    }
    let file = File::open(path).context("golden PNG cannot be opened")?;
    let mut reader = ImageReader::new(BufReader::new(file))
        .with_guessed_format()
        .context("golden image format cannot be detected")?;
    if reader.format() != Some(ImageFormat::Png) {
        bail!("golden input must be a real PNG, not only a .png extension");
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_ALLOCATION);
    reader.limits(limits);
    let image = reader
        .decode()
        .context("golden PNG decoding failed")?
        .to_rgba8();
    let (width, height) = image.dimensions();
    Ok(DecodedPng {
        width,
        height,
        pixels: image.into_raw(),
    })
}

struct PairResult {
    width: u32,
    height: u32,
    comparison: GoldenComparison,
}

fn compare_pair(
    expected_path: &Path,
    actual_path: &Path,
    masks: &[MaskRect],
    diff_path: Option<&Path>,
) -> Result<PairResult> {
    let expected = decode_png(expected_path)?;
    let actual = decode_png(actual_path)?;
    let expected_width = usize::try_from(expected.width)?;
    let expected_height = usize::try_from(expected.height)?;
    let actual_width = usize::try_from(actual.width)?;
    let actual_height = usize::try_from(actual.height)?;
    let expected_stride = expected_width
        .checked_mul(4)
        .ok_or_else(|| anyhow!("golden expected stride overflow"))?;
    let actual_stride = actual_width
        .checked_mul(4)
        .ok_or_else(|| anyhow!("golden actual stride overflow"))?;
    let comparison = compare_rgba(
        RgbaImage::new(
            expected_width,
            expected_height,
            expected_stride,
            &expected.pixels,
        )?,
        RgbaImage::new(actual_width, actual_height, actual_stride, &actual.pixels)?,
        masks,
    )?;
    if !comparison.is_match()
        && let Some(path) = diff_path
    {
        write_diff(path, &expected, &actual, masks)?;
    }
    Ok(PairResult {
        width: expected.width,
        height: expected.height,
        comparison,
    })
}

fn write_diff(
    path: &Path,
    expected: &DecodedPng,
    actual: &DecodedPng,
    masks: &[MaskRect],
) -> Result<()> {
    if expected.width != actual.width || expected.height != actual.height {
        bail!("golden diff dimensions do not match");
    }
    let width = usize::try_from(expected.width)?;
    let height = usize::try_from(expected.height)?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(expected.pixels.len())?;
    for y in 0..height {
        for x in 0..width {
            let offset = y
                .checked_mul(width)
                .and_then(|value| value.checked_add(x))
                .and_then(|value| value.checked_mul(4))
                .ok_or_else(|| anyhow!("golden diff offset overflow"))?;
            if masks.iter().any(|mask| in_mask(x, y, *mask)) {
                pixels.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let expected_pixel = expected
                .pixels
                .get(offset..offset + 4)
                .ok_or_else(|| anyhow!("golden expected pixel missing"))?;
            let actual_pixel = actual
                .pixels
                .get(offset..offset + 4)
                .ok_or_else(|| anyhow!("golden actual pixel missing"))?;
            if pixel_differs(expected_pixel, actual_pixel) {
                pixels.extend_from_slice(&[255, 0, 255, 255]);
            } else {
                let gray = ((u16::from(actual_pixel[0])
                    + u16::from(actual_pixel[1])
                    + u16::from(actual_pixel[2]))
                    / 3) as u8;
                pixels.extend_from_slice(&[gray, gray, gray, 64]);
            }
        }
    }
    write_png_review_artifact(path, expected.width, expected.height, &pixels)
}

fn in_mask(x: usize, y: usize, mask: MaskRect) -> bool {
    x >= mask.x
        && y >= mask.y
        && x < mask.x.saturating_add(mask.width)
        && y < mask.y.saturating_add(mask.height)
}

fn pixel_differs(expected: &[u8], actual: &[u8]) -> bool {
    expected
        .iter()
        .zip(actual)
        .any(|(left, right)| left.abs_diff(*right) > CHANNEL_DIFFERENCE_THRESHOLD)
}

fn write_png_review_artifact(path: &Path, width: u32, height: u32, pixels: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("golden diff path has no parent"))?;
    fs::create_dir_all(parent).context("golden diff directory cannot be created")?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut temporary_name = path
        .file_name()
        .ok_or_else(|| anyhow!("golden diff path has no file name"))?
        .to_os_string();
    temporary_name.push(format!(".tmp-{}-{sequence}", std::process::id()));
    let temporary = parent.join(temporary_name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("golden diff temporary file already exists or cannot be created")?;
    let encode = image::codecs::png::PngEncoder::new(BufWriter::new(file)).write_image(
        pixels,
        width,
        height,
        ColorType::Rgba8.into(),
    );
    if let Err(error) = encode {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("golden diff PNG encoding failed");
    }
    if let Err(first) = fs::rename(&temporary, path) {
        if !path.is_file() {
            let _ = fs::remove_file(&temporary);
            return Err(first).context("golden diff rename failed");
        }
        fs::remove_file(path).context("golden stale diff cannot be replaced")?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("golden diff replacement rename failed");
        }
    }
    Ok(())
}

fn collect_matrix_pngs(
    root: &Path,
    expected_paths: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, PathBuf>> {
    let mut output = BTreeMap::new();
    for (directory, expected_count) in EXPECTED_COUNTS {
        let matrix_root = root.join(directory);
        let matrix = collect_pngs(&matrix_root)?;
        if matrix.len() != expected_count {
            bail!(
                "golden baseline {directory} has {} PNGs, expected {expected_count}",
                matrix.len()
            );
        }
        for (relative, path) in matrix {
            let relative = PathBuf::from(directory).join(relative);
            if output.insert(relative, path).is_some() {
                bail!("golden baseline path collision");
            }
        }
    }
    if output.len() != EXPECTED_TOTAL {
        bail!("golden baseline total is not {EXPECTED_TOTAL}");
    }
    let actual_paths = output.keys().cloned().collect::<BTreeSet<_>>();
    if &actual_paths != expected_paths {
        bail!("golden baseline names drifted from seed-derived matrix inventory");
    }
    Ok(output)
}

fn collect_pngs(root: &Path) -> Result<BTreeMap<PathBuf, PathBuf>> {
    if !root.is_dir() {
        bail!("golden PNG root is missing");
    }
    let mut output = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.context("golden PNG tree cannot be walked")?;
        if entry.file_type().is_symlink() {
            bail!("golden PNG tree contains a symlink");
        }
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("png")
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| anyhow!("golden PNG escaped its root"))?
            .to_path_buf();
        if output
            .insert(relative, entry.path().to_path_buf())
            .is_some()
        {
            bail!("golden PNG inventory contains a duplicate path");
        }
    }
    Ok(output)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_testkit::golden::FULL_DIFFERENCE_BLOCK_SIZE;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "openbot-golden-gate-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .to_path_buf()
    }

    fn png(path: &Path, width: u32, height: u32, pixels: &[u8]) {
        write_png_review_artifact(path, width, height, pixels).unwrap();
    }

    #[test]
    fn repository_manifest_is_structurally_current_but_not_falsely_ready() {
        let rules = ManifestRules::load(&workspace().join(DEFAULT_MANIFEST)).unwrap();
        assert!(!rules.ready);
        assert!(rules.allowed_masks.is_empty());
        assert_eq!(rules.expected_paths.len(), 245);
        for expected in [
            "web/home.light.1440x900.png",
            "web/channel--ch-orders.dark.1024x640.png",
            "web/admin--plugins--notes--tools--search_notes.zh-CN.light.1440x900.png",
            "web/design-gallery.dark.1440x900.png",
            "macos-arm64/memory.light.1440x900.png",
            "windows-x64/settings--connected-accounts--notes.dark.1440x900.png",
        ] {
            assert!(
                rules.expected_paths.contains(Path::new(expected)),
                "{expected}"
            );
        }
        assert!(rules.require_ready().is_err());
    }

    #[test]
    fn route_to_page_key_requires_exact_parameters_and_closed_ascii_segments() {
        assert_eq!(page_key("/", &BTreeMap::new()).unwrap(), "home");
        assert_eq!(
            page_key(
                "/admin/plugins/$key_/tools/$tool",
                &BTreeMap::from([
                    ("key".to_owned(), "notes".to_owned()),
                    ("tool".to_owned(), "search_notes".to_owned()),
                ])
            )
            .unwrap(),
            "admin--plugins--notes--tools--search_notes"
        );
        assert!(page_key("/channel/$channelId", &BTreeMap::new()).is_err());
        assert!(
            page_key(
                "/bad",
                &BTreeMap::from([("unused".to_owned(), "x".to_owned())])
            )
            .is_err()
        );
        assert!(page_key("/bad space", &BTreeMap::new()).is_err());
        assert_eq!(
            dimensions_from_name(Path::new("web/home.light.1440x900.png")).unwrap(),
            (1_440, 900)
        );
        assert!(dimensions_from_name(Path::new("web/home.light.800x600.png")).is_err());
    }

    #[test]
    fn formal_inventory_rejects_empty_and_count_only_wrong_names() {
        let rules = ManifestRules::load(&workspace().join(DEFAULT_MANIFEST)).unwrap();
        let temp = TempRoot::new();
        for directory in ["web", "macos-arm64", "windows-x64"] {
            fs::create_dir(temp.0.join(directory)).unwrap();
        }
        assert!(collect_matrix_pngs(&temp.0, &rules.expected_paths).is_err());

        for relative in &rules.expected_paths {
            let path = temp.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, []).unwrap();
        }
        assert_eq!(
            collect_matrix_pngs(&temp.0, &rules.expected_paths)
                .unwrap()
                .len(),
            245
        );

        fs::remove_file(temp.0.join("web/home.light.1440x900.png")).unwrap();
        fs::write(temp.0.join("web/wrong.light.1440x900.png"), []).unwrap();
        assert!(collect_matrix_pngs(&temp.0, &rules.expected_paths).is_err());
    }

    #[test]
    fn png_pair_uses_exact_ratio_threshold_and_writes_a_deterministic_diff() {
        let temp = TempRoot::new();
        let expected = temp.0.join("expected.png");
        let actual = temp.0.join("actual.png");
        let diff = temp.0.join("diff.png");
        let expected_pixels = vec![0_u8; 1_000 * 4];
        let mut actual_pixels = expected_pixels.clone();
        actual_pixels[0] = 17;
        png(&expected, 1_000, 1, &expected_pixels);
        png(&actual, 1_000, 1, &actual_pixels);
        assert!(
            compare_pair(&expected, &actual, &[], Some(&diff))
                .unwrap()
                .comparison
                .is_match()
        );
        assert!(!diff.exists());

        actual_pixels[4] = 17;
        png(&actual, 1_000, 1, &actual_pixels);
        let first = compare_pair(&expected, &actual, &[], Some(&diff)).unwrap();
        assert!(!first.comparison.is_match());
        let first_bytes = fs::read(&diff).unwrap();
        let second = compare_pair(&expected, &actual, &[], Some(&diff)).unwrap();
        assert!(!second.comparison.is_match());
        assert_eq!(fs::read(&diff).unwrap(), first_bytes);
        assert_eq!(
            decode_png(&diff).unwrap().pixels[0..8],
            [255, 0, 255, 255, 255, 0, 255, 255]
        );
    }

    #[test]
    fn eight_by_eight_block_fails_even_at_the_ratio_boundary() {
        let temp = TempRoot::new();
        let expected = temp.0.join("expected.png");
        let actual = temp.0.join("actual.png");
        let width = 1_000_usize;
        let height = 64_usize;
        let expected_pixels = vec![0_u8; width * height * 4];
        let mut actual_pixels = expected_pixels.clone();
        for y in 0..FULL_DIFFERENCE_BLOCK_SIZE {
            for x in 0..FULL_DIFFERENCE_BLOCK_SIZE {
                actual_pixels[(y * width + x) * 4] = 17;
            }
        }
        png(&expected, width as u32, height as u32, &expected_pixels);
        png(&actual, width as u32, height as u32, &actual_pixels);
        let result = compare_pair(&expected, &actual, &[], None).unwrap();
        assert!(!result.comparison.difference_ratio_exceeded());
        assert!(result.comparison.has_full_difference_block());
        assert!(!result.comparison.is_match());
    }

    #[test]
    fn disguised_non_png_and_dimension_mismatch_fail_closed() {
        let temp = TempRoot::new();
        let fake = temp.0.join("fake.png");
        fs::write(&fake, b"not a png").unwrap();
        assert!(decode_png(&fake).is_err());

        let expected = temp.0.join("expected.png");
        let actual = temp.0.join("actual.png");
        png(&expected, 2, 2, &[0; 16]);
        png(&actual, 1, 4, &[0; 16]);
        assert!(compare_pair(&expected, &actual, &[], None).is_err());
    }

    #[test]
    fn unreviewed_mask_sidecar_is_rejected_when_manifest_allowlist_is_empty() {
        let temp = TempRoot::new();
        let sidecar = temp.0.join("mask.json");
        fs::write(
            &sidecar,
            br#"{"schema":"openbot-golden-mask-resolution-v1","image":"web/a.png","page":"/","rectangles":[{"selector":"[data-golden-mask]","x":0,"y":0,"width":1,"height":1}]}"#,
        )
        .unwrap();
        let rules = ManifestRules::load(&workspace().join(DEFAULT_MANIFEST)).unwrap();
        assert!(load_masks(&sidecar, Some("web/a.png"), &rules).is_err());
    }
}
