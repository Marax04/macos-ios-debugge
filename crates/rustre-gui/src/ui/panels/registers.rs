// ============================================================================
// ui/panels/registers.rs — Full CPU register panel with all register groups,
// flag breakdown, SIMD preview, and dirty-value highlighting.
// ============================================================================
use crate::core::app_state::AppData;
use crate::core::types::{Register, RegisterGroup};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled,
};

// ── Public entry point ────────────────────────────────────────────────────────

pub fn render_registers_panel(data: &AppData) -> impl IntoElement + '_ {
    let regs: Vec<&Register> = data.registers.values().collect();

    let gp: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::General)
        .collect();
    let flags: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Flags)
        .collect();
    let segs: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Segment)
        .collect();
    let fpu: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Fpu)
        .collect();
    let simd: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Simd)
        .collect();
    let ctrl: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Control)
        .collect();
    let dbgregs: Vec<_> = regs
        .iter()
        .filter(|r| r.group == RegisterGroup::Debug)
        .collect();

    let flags_value: Option<u64> = flags
        .iter()
        .find(|r| {
            let n = r.name.to_uppercase();
            n == "RFLAGS" || n == "EFLAGS" || n == "FLAGS"
        })
        .map(|r| r.value);

    let is_attached = data.dbg_attached;
    let pc = data.pc;

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(reg_panel_header(is_attached, pc.0))
        .child(
            div()
                .id("registers-scroll")
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .overflow_y_scroll()
                .p_1()
                // General-Purpose
                .child(reg_group_hdr("General-Purpose", gp.len()))
                .children(gp.iter().map(|r| reg_row(r)))
                // Flags + bit breakdown
                .child(reg_group_hdr("Flags", flags.len()))
                .children(flags.iter().map(|r| reg_row(r)))
                .child(flags_value.map_or_else(
                    || div().into_any_element(),
                    |v| flags_breakdown(v).into_any_element(),
                ))
                // Segment
                .child(reg_group_hdr("Segment", segs.len()))
                .children(segs.iter().map(|r| reg_row(r)))
                // Control
                .child(if ctrl.is_empty() {
                    div().into_any_element()
                } else {
                    div()
                        .child(reg_group_hdr("Control", ctrl.len()))
                        .children(ctrl.iter().map(|r| reg_row(r)))
                        .into_any_element()
                })
                // FPU
                .child(if fpu.is_empty() {
                    div().into_any_element()
                } else {
                    div()
                        .child(reg_group_hdr("FPU / ST(n)", fpu.len()))
                        .children(fpu.iter().map(|r| reg_row_fpu(r)))
                        .into_any_element()
                })
                // SIMD
                .child(if simd.is_empty() {
                    div().into_any_element()
                } else {
                    div()
                        .child(reg_group_hdr("SIMD / XMM / YMM", simd.len()))
                        .children(simd.iter().map(|r| reg_row_simd(r)))
                        .into_any_element()
                })
                // Debug registers
                .child(if dbgregs.is_empty() {
                    div().into_any_element()
                } else {
                    div()
                        .child(reg_group_hdr("Debug Registers", dbgregs.len()))
                        .children(dbgregs.iter().map(|r| reg_row(r)))
                        .into_any_element()
                })
                // Placeholder when idle
                .child(if is_attached {
                    div().into_any_element()
                } else {
                    no_session_hint().into_any_element()
                }),
        )
}

// ── Panel header ──────────────────────────────────────────────────────────────

fn reg_panel_header(is_attached: bool, pc: u64) -> impl IntoElement {
    let status_bg = if is_attached {
        colors::ok()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.3,
            a: 1.0,
        }
    };
    let status_text = if is_attached { "LIVE" } else { "IDLE" };

    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(28.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Registers")
                        .truncate(),
                )
                .child(
                    div()
                        .px(px(5.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .rounded_sm()
                        .bg(status_bg)
                        .text_size(px(8.5))
                        .text_color(Hsla {
                            h: 0.0,
                            s: 0.0,
                            l: 0.06,
                            a: 1.0,
                        })
                        .font_weight(FontWeight::BOLD)
                        .child(status_text)
                        .truncate(),
                ),
        )
        .child(if is_attached && pc != 0 {
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(4.0))
                .child(
                    div()
                        .text_size(px(9.0))
                        .text_color(colors::text_muted())
                        .child("PC")
                        .truncate(),
                )
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(10.0))
                        .text_color(colors::syn_address())
                        .child(format!("{pc:#018x}"))
                        .truncate(),
                )
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

// ── Group header ──────────────────────────────────────────────────────────────

fn reg_group_hdr(label: &'static str, count: usize) -> impl IntoElement {
    div()
        .h(px(18.0))
        .px_2()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .bg(colors::bg_elevated())
        .border_t_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child(label)
                .truncate(),
        )
        .child(
            div()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .child(format!("{count}"))
                .truncate(),
        )
}

// ── Standard register row ─────────────────────────────────────────────────────

fn reg_row(r: &Register) -> impl IntoElement {
    let (hex_str, dec_str) = format_reg_value(r);
    let dirty = r.dirty;
    let val_color = if dirty {
        colors::warn()
    } else {
        colors::syn_immediate()
    };
    let row_bg = if dirty {
        Hsla {
            h: 0.08,
            s: 0.5,
            l: 0.14,
            a: 0.3,
        }
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 2.0))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.14,
            a: 0.35,
        })
        .bg(row_bg)
        .hover(|s| s.bg(colors::bg_hover()))
        // Name
        .child(
            div()
                .w(px(56.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_register())
                .font_weight(FontWeight::SEMIBOLD)
                .child(r.name.clone())
                .truncate(),
        )
        // Hex value
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(val_color)
                .child(hex_str)
                .truncate(),
        )
        // Decimal (narrow)
        .child(
            div()
                .w(px(86.0))
                .font_family("JetBrains Mono")
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .child(dec_str)
                .truncate(),
        )
        // Dirty dot
        .child(if dirty {
            div()
                .w(px(5.0))
                .h(px(5.0))
                .rounded_sm()
                .bg(colors::warn())
                .flex_shrink_0()
                .into_any_element()
        } else {
            div().w(px(5.0)).into_any_element()
        })
}

// ── FPU register row ──────────────────────────────────────────────────────────

fn reg_row_fpu(r: &Register) -> impl IntoElement {
    let dirty = r.dirty;
    let val_color = if dirty {
        colors::warn()
    } else {
        colors::syn_immediate()
    };
    // Interpret the 64-bit raw bits as a double
    let float_str = format!("{:.10e}", f64::from_bits(r.value));

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 4.0))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.14,
            a: 0.35,
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(56.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_register())
                .font_weight(FontWeight::SEMIBOLD)
                .child(r.name.clone())
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(sizes::CODE - 1.5))
                        .text_color(val_color)
                        .child(format!("{:#018x}", r.value))
                        .truncate(),
                )
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(9.0))
                        .text_color(colors::text_muted())
                        .child(format!("f64 ≈ {float_str}"))
                        .truncate(),
                ),
        )
}

// ── SIMD register row ─────────────────────────────────────────────────────────

fn reg_row_simd(r: &Register) -> impl IntoElement {
    let dirty = r.dirty;
    let val_color = if dirty {
        colors::warn()
    } else {
        colors::syn_immediate()
    };

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 4.0))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.14,
            a: 0.35,
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .w(px(56.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_register())
                .font_weight(FontWeight::SEMIBOLD)
                .child(r.name.clone())
                .truncate(),
        )
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(9.5))
                        .text_color(val_color)
                        .child(format!("lo: {:#018x}", r.value))
                        .truncate(),
                )
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(8.5))
                        .text_color(colors::text_muted())
                        .child(format!("f64: {:>16.6e}", f64::from_bits(r.value)))
                        .truncate(),
                ),
        )
}

// ── FLAGS bit breakdown ───────────────────────────────────────────────────────

const FLAG_BITS: &[(&str, u8)] = &[
    ("CF", 0),   // Carry
    ("PF", 2),   // Parity
    ("AF", 4),   // Auxiliary carry
    ("ZF", 6),   // Zero
    ("SF", 7),   // Sign
    ("TF", 8),   // Trap
    ("IF", 9),   // Interrupt enable
    ("DF", 10),  // Direction
    ("OF", 11),  // Overflow
    ("NT", 14),  // Nested task
    ("RF", 16),  // Resume
    ("VM", 17),  // Virtual 8086 mode
    ("AC", 18),  // Alignment check
    ("VIF", 19), // Virtual interrupt flag
    ("VIP", 20), // Virtual interrupt pending
    ("ID", 21),  // CPUID support
];

fn flags_breakdown(value: u64) -> impl IntoElement {
    div()
        .mx_2()
        .mb_1()
        .p(px(4.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .flex()
        .flex_row()
        .flex_wrap()
        .gap(px(3.0))
        .children(FLAG_BITS.iter().map(|(name, bit)| {
            let set = (value >> bit) & 1 == 1;
            let chip_bg = if set { colors::ok() } else { colors::bg_base() };
            let chip_text = if set {
                Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.05,
                    a: 1.0,
                }
            } else {
                colors::text_muted()
            };
            let chip_border = if set { colors::ok() } else { colors::border() };
            div()
                .px(px(4.0))
                .h(px(15.0))
                .flex()
                .items_center()
                .rounded_sm()
                .bg(chip_bg)
                .border_1()
                .border_color(chip_border)
                .child(
                    div()
                        .font_family("JetBrains Mono")
                        .text_size(px(8.5))
                        .text_color(chip_text)
                        .child(*name)
                        .truncate(),
                )
        }))
}

// ── No-session placeholder ────────────────────────────────────────────────────

fn no_session_hint() -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .w_full()
        .pt(px(20.0))
        .gap(px(6.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .child("No active debug session")
                .truncate(),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .child("Attach or launch a process to see registers.")
                .truncate(),
        )
}

// ── Value formatting ──────────────────────────────────────────────────────────

fn format_reg_value(r: &Register) -> (String, String) {
    match r.width {
        8 => (
            format!("0x{:02x}", u8::try_from(r.value).unwrap_or(u8::MAX)),
            format!("{:5}", i8::try_from(r.value).unwrap_or(i8::MAX)),
        ),
        16 => (
            format!("0x{:04x}", u16::try_from(r.value).unwrap_or(u16::MAX)),
            format!("{:6}", i16::try_from(r.value).unwrap_or(i16::MAX)),
        ),
        32 => (
            format!("0x{:08x}", u32::try_from(r.value).unwrap_or(u32::MAX)),
            format!("{:11}", i32::try_from(r.value).unwrap_or(i32::MAX)),
        ),
        _ => (
            format!("0x{:016x}", r.value),
            format!("{:20}", i64::try_from(r.value).unwrap_or(i64::MAX)),
        ),
    }
}
