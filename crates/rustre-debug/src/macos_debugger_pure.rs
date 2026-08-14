//! Host-independent map-labelling logic used by `macos_debugger.rs`.
//!
//! # Why this is its own module
//!
//! `macos_debugger.rs` is `#![cfg(target_os = "macos")]`, so everything in it
//! — including its `#[cfg(test)] mod tests` — is invisible on a non-macOS
//! host: never compiled, never run, never able to fail. The same reasoning
//! that produced `macho_image_size` applies here. Every function below is
//! pure (no `task_t`, no syscall, no live process), so it is compiled and
//! genuinely EXERCISED by the suite on Windows and Linux, which is the only
//! real coverage this backend can get in this environment.
//!
//! The impure half stays in `macos_debugger.rs`: enumerating the target's VM
//! regions and dyld images, both of which need a live Mach task port.

use crate::{Address, MemoryMap, ModuleInfo};

/// Attach module names/paths to memory regions by containment.
///
/// Darwin's `mach_vm_region_recurse` — unlike `/proc/<pid>/maps` on Linux and
/// unlike `VirtualQueryEx` + `GetMappedFileName` on Windows — reports
/// permissions and sizes but no backing file, so `walk_vm_regions` emits every
/// region with `name: None, file_path: None`. A memory map where nothing is
/// named is close to useless to a human: "which of these 300 ranges is the
/// executable?" has no answer. The dyld image list already carries base, size,
/// name and path, so the two can simply be cross-referenced.
///
/// A region belongs to the image whose `[base, base + size)` contains the
/// region's base. When several images contain it (images can be nested, and a
/// zero-size image degenerates to no range at all), the one with the HIGHEST
/// base wins: that is the innermost, most specific enclosing image.
///
/// Regions matching no image keep `None` — an unnamed anonymous mapping is
/// the truth for stacks, heaps and JIT pages, and inventing a name for them
/// would be worse than saying nothing.
pub fn label_maps(maps: &mut [MemoryMap], images: &[ModuleInfo]) {
    for map in maps.iter_mut() {
        let addr = map.base.as_u64();
        let best = images
            .iter()
            .filter(|img| {
                let base = img.base.as_u64();
                // `checked_add` rather than `+`: `size` comes from a target
                // process's own Mach-O header and a garbage value must not
                // wrap the range into something that matches everything.
                base.checked_add(img.size).is_some_and(|end| addr >= base && addr < end)
            })
            .max_by_key(|img| img.base.as_u64());
        if let Some(img) = best {
            map.name = Some(img.name.clone());
            if !img.path.is_empty() {
                map.file_path = Some(img.path.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_at(base: u64) -> MemoryMap {
        MemoryMap {
            base: Address(base),
            size: 0x1000,
            readable: true,
            writable: false,
            executable: true,
            name: None,
            file_path: None,
            file_offset: 0,
        }
    }

    fn image(name: &str, path: &str, base: u64, size: u64) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: path.to_string(),
            base: Address(base),
            size,
            entry_point: None,
            is_main: false,
        }
    }

    #[test]
    fn a_region_inside_an_image_is_labelled_with_that_images_name_and_path() {
        let mut maps = vec![map_at(0x1_0000), map_at(0x1_2000)];
        let images = vec![image("app", "/usr/bin/app", 0x1_0000, 0x4000)];
        label_maps(&mut maps, &images);
        for m in &maps {
            assert_eq!(m.name.as_deref(), Some("app"));
            assert_eq!(m.file_path.as_deref(), Some("/usr/bin/app"));
        }
    }

    #[test]
    fn a_region_outside_every_image_stays_unnamed() {
        // Stacks, heaps and JIT pages back onto no file; naming them would be
        // a fabrication, and the end of the range is exclusive.
        let mut maps = vec![map_at(0x9_0000), map_at(0x1_4000)];
        let images = vec![image("app", "/usr/bin/app", 0x1_0000, 0x4000)];
        label_maps(&mut maps, &images);
        assert!(maps[0].name.is_none(), "unrelated region must not be labelled");
        assert!(
            maps[1].name.is_none(),
            "base + size is EXCLUSIVE: 0x14000 is the first byte after the image"
        );
    }

    #[test]
    fn the_innermost_of_two_overlapping_images_wins() {
        let mut maps = vec![map_at(0x2_0000)];
        let images = vec![
            image("outer", "/outer", 0x1_0000, 0x10_0000),
            image("inner", "/inner", 0x2_0000, 0x1000),
        ];
        label_maps(&mut maps, &images);
        assert_eq!(maps[0].name.as_deref(), Some("inner"));
    }

    #[test]
    fn an_image_whose_size_would_overflow_does_not_match_everything() {
        // `size` is read out of the target's own Mach-O header. A garbage
        // value near u64::MAX must not make one image swallow the whole
        // address space via a wrapped end address.
        let mut maps = vec![map_at(0x1000)];
        let images = vec![image("bogus", "/bogus", u64::MAX - 8, u64::MAX)];
        label_maps(&mut maps, &images);
        assert!(maps[0].name.is_none(), "an overflowing image range must match nothing");
    }
}
