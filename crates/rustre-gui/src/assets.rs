// ============================================================================
// assets.rs — Embedded asset source for GPUI (icons, fonts, etc.)
// All files in assets/ are embedded at compile time via include_dir!
// ============================================================================

use gpui::{AssetSource, SharedString};
use include_dir::{include_dir, Dir};
use std::borrow::Cow;

static ASSETS_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/assets");

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        ASSETS_DIR
            .get_file(path)
            .map_or_else(|| Ok(None), |file| Ok(Some(Cow::Borrowed(file.contents()))))
    }

    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        Ok(ASSETS_DIR
            .get_dir(path)
            .map(|dir| {
                dir.files()
                    .map(|f| SharedString::from(f.path().to_string_lossy().replace('\\', "/")))
                    .collect()
            })
            .unwrap_or_default())
    }
}
