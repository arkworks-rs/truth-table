use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    setup::KeyGenerator,
};
use ark_serialize::CanonicalSerialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

pub const DEFAULT_TEST_LOG_SIZE: usize = 16;
pub const DEFAULT_BENCH_LOG_SIZE: usize = 20;
pub const DEFAULT_LOG_SIZE: usize = DEFAULT_TEST_LOG_SIZE;
const DEFAULT_PK_FILE: &str = "tt_proving_key";
const DEFAULT_VK_FILE: &str = "tt_verifying_key";

pub struct SetupBuilder {
    size_label: Option<String>,
    pk_path: Option<PathBuf>,
    vk_path: Option<PathBuf>,
}

impl Default for SetupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupBuilder {
    pub fn new() -> Self {
        Self {
            size_label: None,
            pk_path: None,
            vk_path: None,
        }
    }

    pub fn with_size_label(mut self, size: Option<String>) -> Self {
        self.size_label = size;
        self
    }

    pub fn with_pk_path(mut self, path: Option<PathBuf>) -> Self {
        self.pk_path = path;
        self
    }

    pub fn with_vk_path(mut self, path: Option<PathBuf>) -> Self {
        self.vk_path = path;
        self
    }

    pub fn build(self) -> Result<SetupRunner> {
        let log_size = parse_log_size(self.size_label)?;

        let (pk_path, vk_path) = match (self.pk_path, self.vk_path) {
            (Some(pk), Some(vk)) => (pk, vk),
            (None, None) => {
                let base = std::env::current_dir()
                    .context("failed to resolve current working directory")?;
                let pk = base.join(default_pk_filename(log_size));
                let vk = base.join(default_vk_filename(log_size));
                (pk, vk)
            }
            (Some(pk), None) => {
                let base = pk
                    .parent()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                let vk = base.join(default_vk_filename(log_size));
                (pk, vk)
            }
            (None, Some(vk)) => {
                let base = vk
                    .parent()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                let pk = base.join(default_pk_filename(log_size));
                (pk, vk)
            }
        };

        Ok(SetupRunner {
            log_size,
            pk_path,
            vk_path,
        })
    }
}

pub struct SetupRunner {
    log_size: usize,
    pk_path: PathBuf,
    vk_path: PathBuf,
}

impl SetupRunner {
    pub fn run(&self) -> Result<()> {
        let keygen = KeyGenerator::<B>::new().with_num_mv_vars(self.log_size);

        let (pk, vk) = keygen
            .gen_keys()
            .map_err(|e| anyhow!("failed to generate keys: {e}"))?;

        write_key(&pk, &self.pk_path)?;
        write_key(&vk, &self.vk_path)?;

        Ok(())
    }
}

fn parse_log_size(label: Option<String>) -> Result<usize> {
    match label {
        Some(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "small" | "test" => Ok(DEFAULT_TEST_LOG_SIZE),
                "medium" | "bench" => Ok(DEFAULT_BENCH_LOG_SIZE),
                "large" => Ok(23),
                other => other
                    .parse::<usize>()
                    .map_err(|_| anyhow!("invalid size '{other}'")),
            }
        }
        None => Ok(DEFAULT_LOG_SIZE),
    }
}

pub fn default_pk_filename(log_size: usize) -> String {
    format!("{DEFAULT_PK_FILE}_{log_size}.pk")
}

pub fn default_vk_filename(log_size: usize) -> String {
    format!("{DEFAULT_VK_FILE}_{log_size}.vk")
}

fn write_key<T: CanonicalSerialize>(value: &T, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let mut file = fs::File::create(path)
        .with_context(|| format!("failed to open {} for writing", path.display()))?;
    value
        .serialize_uncompressed(&mut file)
        .map_err(|err| anyhow!("failed to serialize artifact to {}: {err}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(())
}
