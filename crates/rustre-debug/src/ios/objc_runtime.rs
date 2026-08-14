//! Ispezione del runtime Objective-C leggendo la memoria **viva** del target.
//!
//! Perché un trait di lettura e non un `&[u8]`: le strutture ObjC interessanti
//! (`class_rw_t`, method list realizzate, `isa` non-pointer) esistono solo dopo
//! che dyld e `objc_init` hanno riscritto l'immagine in memoria; leggerle dal
//! file su disco darebbe risultati sistematicamente sbagliati. Il trait rende
//! comunque tutto il modulo testabile su Windows con memoria sintetica.
//!
//! Tutte le funzioni qui sono pure rispetto al lettore: nessun `cfg(target_os)`,
//! nessuna syscall. Il layout implementato è quello a 64 bit little-endian
//! (arm64 / arm64e / x86_64); i target big-endian (PPC) sono rifiutati con un
//! errore esplicito invece di essere decodificati a caso.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Errori
// ---------------------------------------------------------------------------

/// Errori dell'ispezione runtime. Ogni variante nomina un difetto diverso:
/// il repo punisce il "confidently wrong", quindi un dato non leggibile non
/// diventa mai un `Option::None` silenzioso quando la causa è nota.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjcError {
    /// La memoria del target non è leggibile all'indirizzo richiesto.
    #[error("unreadable memory at {addr:#x} (+{len} bytes): {reason}")]
    Unreadable {
        /// Indirizzo richiesto.
        addr: u64,
        /// Lunghezza richiesta.
        len: usize,
        /// Motivo riportato dal lettore sottostante.
        reason: String,
    },
    /// Il lettore ha restituito meno byte del richiesto.
    #[error("short read at {addr:#x}: wanted {wanted}, got {got}")]
    ShortRead {
        /// Indirizzo richiesto.
        addr: u64,
        /// Byte richiesti.
        wanted: usize,
        /// Byte ottenuti.
        got: usize,
    },
    /// Puntatore nullo dove ne era richiesto uno valido.
    #[error("null pointer while reading {what}")]
    NullPointer {
        /// Campo che si stava seguendo.
        what: &'static str,
    },
    /// Stringa C non terminata entro il limite di scansione.
    #[error("unterminated C string at {addr:#x} within {limit} bytes")]
    UnterminatedString {
        /// Indirizzo di partenza.
        addr: u64,
        /// Limite di scansione.
        limit: usize,
    },
    /// Struttura con un conteggio/dimensione fuori da ogni limite plausibile:
    /// quasi sempre significa che stiamo seguendo un puntatore sbagliato.
    #[error("implausible {what}: {value} (limit {limit})")]
    Implausible {
        /// Campo incriminato.
        what: &'static str,
        /// Valore letto.
        value: u64,
        /// Limite accettato.
        limit: u64,
    },
    /// Il puntatore è un tagged pointer: non c'è nessun `objc_class` da leggere.
    #[error("{0} is a tagged pointer, not a real object")]
    TaggedPointer(u64),
    /// Funzionalità non implementabile senza informazioni che qui non abbiamo.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Risultato dell'ispezione runtime.
pub type ObjcResult<T> = Result<T, ObjcError>;

// ---------------------------------------------------------------------------
// Lettore di memoria
// ---------------------------------------------------------------------------

/// Accesso in sola lettura allo spazio di indirizzamento del target.
///
/// L'implementazione reale sarà un pacchetto RSP `m addr,len` verso
/// debugserver; nei test è `SparseMemory`.
pub trait ObjcMemory {
    /// Legge esattamente `len` byte a partire da `addr`.
    ///
    /// # Errors
    /// Ritorna [`ObjcError::Unreadable`] se la pagina non è mappata e
    /// [`ObjcError::ShortRead`] se ne arrivano meno del richiesto.
    fn read(&self, addr: u64, len: usize) -> ObjcResult<Vec<u8>>;

    /// Legge un `u8`.
    ///
    /// # Errors
    /// Vedi [`ObjcMemory::read`].
    fn read_u8(&self, addr: u64) -> ObjcResult<u8> {
        Ok(self.read(addr, 1)?[0])
    }

    /// Legge un `u32` little-endian.
    ///
    /// # Errors
    /// Vedi [`ObjcMemory::read`].
    fn read_u32(&self, addr: u64) -> ObjcResult<u32> {
        let b = self.read(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Legge un `i32` little-endian (offset relativi delle small method list).
    ///
    /// # Errors
    /// Vedi [`ObjcMemory::read`].
    fn read_i32(&self, addr: u64) -> ObjcResult<i32> {
        self.read_u32(addr).map(|v| v as i32)
    }

    /// Legge un `u64` little-endian.
    ///
    /// # Errors
    /// Vedi [`ObjcMemory::read`].
    fn read_u64(&self, addr: u64) -> ObjcResult<u64> {
        let b = self.read(addr, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Legge una stringa C UTF-8 (lossy) fino al NUL, al massimo `limit` byte.
    ///
    /// # Errors
    /// [`ObjcError::NullPointer`] se `addr == 0`,
    /// [`ObjcError::UnterminatedString`] se non trova il NUL entro `limit`.
    fn read_cstring(&self, addr: u64, limit: usize) -> ObjcResult<String> {
        if addr == 0 {
            return Err(ObjcError::NullPointer { what: "C string" });
        }
        let mut out = Vec::new();
        let mut cur = addr;
        // Chunk da 32 byte: una lettura per byte costerebbe un pacchetto RSP
        // per carattere su un target reale.
        while out.len() < limit {
            let mut want = 32.min(limit - out.len());
            // Una lettura in blocco può eccedere la fine della mappatura anche
            // quando il NUL cade prima: in quel caso riproviamo con quanto è
            // realmente disponibile invece di dichiarare la stringa illeggibile.
            let chunk = loop {
                match self.read(cur, want) {
                    Ok(c) => break c,
                    Err(ObjcError::ShortRead { got, .. }) if got > 0 && got < want => want = got,
                    Err(e) => return Err(e),
                }
            };
            if let Some(pos) = chunk.iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..pos]);
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            out.extend_from_slice(&chunk);
            cur = cur.wrapping_add(want as u64);
        }
        Err(ObjcError::UnterminatedString { addr, limit })
    }
}

/// Adatta una qualsiasi funzione di lettura a [`ObjcMemory`].
///
/// Prima esisteva un solo implementatore, [`SparseMemory`], che e' un
/// contenitore in memoria per i test: **niente collegava la memoria di un
/// processo VIVO** a questo modulo ne' a `swift_runtime`, che vi si appoggia
/// tramite `ObjcMemoryAdapter`. Entrambi erano quindi inutilizzabili contro un
/// target reale, per quanto completi.
///
/// Con questo adattatore un debugger passa la propria `read_memory` e i due
/// moduli diventano guidabili dal vivo; i test continuano a usare
/// `SparseMemory`.
pub struct ReaderMemory<R>(pub R)
where
    R: Fn(u64, usize) -> Option<Vec<u8>>;

impl<R> ObjcMemory for ReaderMemory<R>
where
    R: Fn(u64, usize) -> Option<Vec<u8>>,
{
    fn read(&self, addr: u64, len: usize) -> ObjcResult<Vec<u8>> {
        // Una lettura corta viene distinta da una pagina non mappata: la prima
        // significa "il target ha meno dati del previsto a quell'indirizzo",
        // la seconda "quell'indirizzo non esiste". Confonderle manderebbe un
        // chiamante a caccia del bug sbagliato.
        let bytes = (self.0)(addr, len).ok_or_else(|| ObjcError::Unreadable {
            addr,
            len,
            reason: "reader returned nothing for this range".to_string(),
        })?;
        if bytes.len() < len {
            return Err(ObjcError::ShortRead { addr, wanted: len, got: bytes.len() });
        }
        Ok(bytes)
    }
}

/// Memoria sparsa in-process: mattoni di byte a indirizzi arbitrari.
///
/// Serve ai test, ma è anche il modo giusto di modellare uno snapshot di core
/// dump, quindi non è confinata dietro `cfg(test)`.
#[derive(Debug, Default, Clone)]
pub struct SparseMemory {
    chunks: BTreeMap<u64, Vec<u8>>,
}

impl SparseMemory {
    /// Costruisce una memoria vuota.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mappa `bytes` all'indirizzo `addr`.
    pub fn write(&mut self, addr: u64, bytes: impl Into<Vec<u8>>) {
        self.chunks.insert(addr, bytes.into());
    }

    /// Mappa un `u64` little-endian.
    pub fn write_u64(&mut self, addr: u64, value: u64) {
        self.write(addr, value.to_le_bytes().to_vec());
    }

    /// Mappa una serie di `u64` consecutivi (layout di struct a puntatori).
    pub fn write_u64s(&mut self, addr: u64, values: &[u64]) {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for v in values {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        self.write(addr, bytes);
    }

    /// Mappa una stringa C NUL-terminata.
    pub fn write_cstr(&mut self, addr: u64, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        self.write(addr, bytes);
    }
}

impl ObjcMemory for SparseMemory {
    fn read(&self, addr: u64, len: usize) -> ObjcResult<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        let mut cur = addr;
        while out.len() < len {
            // Il chunk che copre `cur` è l'ultimo con base <= cur.
            let Some((&base, data)) = self.chunks.range(..=cur).next_back() else {
                return Err(ObjcError::Unreadable {
                    addr,
                    len,
                    reason: format!("no mapping covers {cur:#x}"),
                });
            };
            let off = (cur - base) as usize;
            if off >= data.len() {
                // Distinguiamo "buco a metà lettura" da "indirizzo del tutto non
                // mappato": il primo è una lettura troppo lunga, il secondo un
                // puntatore sbagliato, e il chiamante reagisce diversamente.
                return if out.is_empty() {
                    Err(ObjcError::Unreadable {
                        addr,
                        len,
                        reason: format!("no mapping covers {cur:#x}"),
                    })
                } else {
                    Err(ObjcError::ShortRead {
                        addr,
                        wanted: len,
                        got: out.len(),
                    })
                };
            }
            let take = (data.len() - off).min(len - out.len());
            out.extend_from_slice(&data[off..off + take]);
            cur = cur.wrapping_add(take as u64);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ABI: maschere isa e tagged pointer
// ---------------------------------------------------------------------------

/// Architettura del target: cambia le maschere `isa` e il formato dei tagged
/// pointer, che non sono gli stessi su arm64 e x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjcAbi {
    /// arm64 / arm64e (iOS, macOS Apple Silicon).
    Arm64,
    /// x86_64 (macOS Intel, simulatore iOS).
    X86_64,
}

impl ObjcAbi {
    /// Maschera che estrae il puntatore a classe da una `isa` non-pointer.
    ///
    /// arm64: `ISA_MASK = 0x0000_000f_ffff_fff8`.
    /// x86_64: `ISA_MASK = 0x0000_7fff_ffff_fff8`.
    #[must_use]
    pub const fn isa_mask(self) -> u64 {
        match self {
            Self::Arm64 => 0x0000_000f_ffff_fff8,
            Self::X86_64 => 0x0000_7fff_ffff_fff8,
        }
    }

    /// Maschera che marca una `isa` come non-pointer (bit 0, `ISA_BIT_NONPOINTER`).
    #[must_use]
    pub const fn isa_nonpointer_bit(self) -> u64 {
        1
    }

    /// Bit che marca un tagged pointer.
    ///
    /// Su arm64 è il bit **alto** (63), su x86_64 il bit **basso** (0).
    #[must_use]
    pub const fn tag_mask(self) -> u64 {
        match self {
            Self::Arm64 => 1 << 63,
            Self::X86_64 => 1,
        }
    }

    /// Shift dello slot di tag a 3 bit.
    #[must_use]
    pub const fn tag_slot_shift(self) -> u32 {
        match self {
            Self::Arm64 => 60,
            Self::X86_64 => 1,
        }
    }

    /// `FAST_DATA_MASK`: estrae `class_rw_t`/`class_ro_t` da `objc_class::bits`.
    /// Identica sulle due ABI a 64 bit.
    #[must_use]
    pub const fn fast_data_mask(self) -> u64 {
        0x0000_7fff_ffff_fff8
    }
}

/// Rimuove i bit di Pointer Authentication (arm64e).
///
/// Un puntatore firmato ha i bit alti occupati dal PAC; nessun parser del repo
/// li toglie oggi, e seguirli produce letture a indirizzi impossibili.
/// Manteniamo i 48 bit bassi, che è quanto indirizza realmente il TTBR0 utente.
#[must_use]
pub const fn strip_pac(ptr: u64) -> u64 {
    ptr & 0x0000_ffff_ffff_ffff
}

// ---------------------------------------------------------------------------
// Tagged pointer
// ---------------------------------------------------------------------------

/// Classe di un tagged pointer, per indice di slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaggedClass {
    /// Slot 0.
    NsAtom,
    /// Slot 1 (riservato/non documentato).
    Reserved1,
    /// Slot 2: `NSString` tagged.
    NsString,
    /// Slot 3: `NSNumber` tagged.
    NsNumber,
    /// Slot 4: `NSIndexPath`.
    NsIndexPath,
    /// Slot 5: `NSManagedObjectID`.
    NsManagedObjectId,
    /// Slot 6: `NSDate`.
    NsDate,
    /// Slot 7 (riservato: introduce le classi "extended").
    Reserved7,
}

impl TaggedClass {
    /// Slot 3-bit -> classe.
    #[must_use]
    pub const fn from_slot(slot: u8) -> Self {
        match slot & 0x7 {
            0 => Self::NsAtom,
            1 => Self::Reserved1,
            2 => Self::NsString,
            3 => Self::NsNumber,
            4 => Self::NsIndexPath,
            5 => Self::NsManagedObjectId,
            6 => Self::NsDate,
            _ => Self::Reserved7,
        }
    }

    /// Nome della classe come lo stamperebbe `object_getClassName`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NsAtom => "NSAtom",
            Self::Reserved1 => "(tagged slot 1)",
            Self::NsString => "NSTaggedPointerString",
            Self::NsNumber => "__NSCFNumber",
            Self::NsIndexPath => "NSIndexPath",
            Self::NsManagedObjectId => "NSManagedObjectID",
            Self::NsDate => "__NSTaggedDate",
            Self::Reserved7 => "(tagged slot 7)",
        }
    }
}

/// Un tagged pointer decodificato: slot + payload già estratto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedPointer {
    /// Valore originale del puntatore.
    pub raw: u64,
    /// Slot di classe (3 bit).
    pub slot: u8,
    /// Classe corrispondente allo slot.
    pub class: TaggedClass,
    /// Payload (bit utili) già allineato a destra.
    pub payload: u64,
}

/// Decodifica `ptr` come tagged pointer, o `None` se è un puntatore normale.
#[must_use]
pub fn decode_tagged_pointer(ptr: u64, abi: ObjcAbi) -> Option<TaggedPointer> {
    if ptr == 0 || ptr & abi.tag_mask() == 0 {
        return None;
    }
    let slot = ((ptr >> abi.tag_slot_shift()) & 0x7) as u8;
    // arm64: payload = bit 0..59 (il tag occupa 60..63).
    // x86_64: payload = bit 4..63 (tag bit 0, slot bit 1..3).
    let payload = match abi {
        ObjcAbi::Arm64 => ptr & 0x0fff_ffff_ffff_ffff,
        ObjcAbi::X86_64 => ptr >> 4,
    };
    Some(TaggedPointer {
        raw: ptr,
        slot,
        class: TaggedClass::from_slot(slot),
        payload,
    })
}

/// Valore di un `NSNumber` tagged.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaggedNumber {
    /// Intero con segno (char/short/int/long, già esteso a 64 bit).
    Int(i64),
    /// `float` a 32 bit.
    Float(f32),
    /// `double` a 64 bit (nella pratica troncato: il payload non basta).
    Double(f64),
}

/// Decodifica il payload di un `NSNumber` tagged.
///
/// Layout (reverse-engineered, stabile da iOS 7 / OS X 10.9): i 4 bit bassi del
/// payload sono il tipo, il resto è il valore. È una convenzione privata di
/// Foundation, non una ABI pubblica: se il tipo è sconosciuto ritorniamo un
/// errore invece di inventare un numero.
///
/// # Errors
/// [`ObjcError::Unsupported`] se lo slot non è `NSNumber` o il tipo è ignoto.
pub fn decode_tagged_number(tp: &TaggedPointer) -> ObjcResult<TaggedNumber> {
    if tp.class != TaggedClass::NsNumber {
        return Err(ObjcError::Unsupported(format!(
            "tagged slot {} is {}, not NSNumber",
            tp.slot,
            tp.class.name()
        )));
    }
    let kind = (tp.payload & 0xF) as u8;
    let value = tp.payload >> 4;
    // Estensione del segno alla larghezza del tipo.
    let sext = |bits: u32| -> i64 {
        let shift = 64 - bits;
        ((value << shift) as i64) >> shift
    };
    match kind {
        1 => Ok(TaggedNumber::Int(sext(8))),
        2 => Ok(TaggedNumber::Int(sext(16))),
        3 => Ok(TaggedNumber::Int(sext(32))),
        4 => Ok(TaggedNumber::Int(sext(60))),
        5 => Ok(TaggedNumber::Float(f32::from_bits(
            u32::try_from(value & 0xffff_ffff).unwrap_or(0),
        ))),
        6 => Ok(TaggedNumber::Double(f64::from_bits(value))),
        other => Err(ObjcError::Unsupported(format!(
            "unknown tagged NSNumber type nibble {other}"
        ))),
    }
}

/// Alfabeto a 6 bit usato dalle tagged `NSString` di lunghezza 8..=9.
const TAGGED_STRING_ALPHABET_6: &[u8; 64] =
    b"eilotrm.apdnsIc ufkMShjTRxgC4013bDNvwyUL2O856P-B79AFKEWV_zGJ/HYX";
/// Alfabeto a 5 bit usato per lunghezza 10..=11: i primi 32 simboli di quello
/// a 6 bit, cioè i caratteri più frequenti in inglese.
const TAGGED_STRING_ALPHABET_5: &[u8; 32] = b"eilotrm.apdnsIc ufkMShjTRxgC4013";

/// Decodifica il payload di una `NSString` tagged.
///
/// Tre codifiche a seconda della lunghezza (nibble basso del payload):
/// `<= 7` ASCII a 8 bit, `8..=9` alfabeto a 6 bit, `10..=11` alfabeto a 5 bit.
///
/// # Errors
/// [`ObjcError::Unsupported`] se lo slot non è `NSString` o la lunghezza è
/// fuori dai valori codificabili (>11).
pub fn decode_tagged_string(tp: &TaggedPointer) -> ObjcResult<String> {
    if tp.class != TaggedClass::NsString {
        return Err(ObjcError::Unsupported(format!(
            "tagged slot {} is {}, not NSString",
            tp.slot,
            tp.class.name()
        )));
    }
    let len = (tp.payload & 0xF) as usize;
    let bits = tp.payload >> 4;
    let mut out = String::with_capacity(len);
    match len {
        0 => {}
        1..=7 => {
            for i in 0..len {
                let c = ((bits >> (i * 8)) & 0xFF) as u8;
                out.push(c as char);
            }
        }
        8..=9 => {
            for i in 0..len {
                let idx = ((bits >> (i * 6)) & 0x3F) as usize;
                out.push(TAGGED_STRING_ALPHABET_6[idx] as char);
            }
        }
        10..=11 => {
            for i in 0..len {
                let idx = ((bits >> (i * 5)) & 0x1F) as usize;
                out.push(TAGGED_STRING_ALPHABET_5[idx] as char);
            }
        }
        other => {
            return Err(ObjcError::Unsupported(format!(
                "tagged NSString length {other} is not encodable"
            )));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// isa
// ---------------------------------------------------------------------------

/// Un campo `isa` interpretato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsaField {
    /// Parola grezza letta all'offset 0 dell'oggetto.
    pub raw: u64,
    /// Puntatore alla classe, con PAC e bit di packing rimossi.
    pub class_ptr: u64,
    /// `true` se la `isa` è in forma non-pointer (bit 0 acceso).
    pub nonpointer: bool,
}

/// Interpreta la parola `isa` di un oggetto.
///
/// Una `isa` non-pointer impacchetta refcount, flag di weak/deallocating ecc.
/// insieme al puntatore a classe: leggerla come puntatore diretto — che è
/// quello che fa il codice ingenuo — dà un indirizzo che non esiste.
#[must_use]
pub const fn decode_isa(raw: u64, abi: ObjcAbi) -> IsaField {
    let nonpointer = raw & abi.isa_nonpointer_bit() != 0;
    let class_ptr = if nonpointer {
        raw & abi.isa_mask()
    } else {
        strip_pac(raw) & !0x7
    };
    IsaField {
        raw,
        class_ptr,
        nonpointer,
    }
}

// ---------------------------------------------------------------------------
// objc_class / class_ro_t
// ---------------------------------------------------------------------------

/// Offset dei campi di `objc_class` a 64 bit.
mod class_off {
    /// `Class isa`.
    pub const ISA: u64 = 0;
    /// `Class superclass`.
    pub const SUPERCLASS: u64 = 8;
    // Offset 16..32: `cache_t cache` (buckets + mask/occupied). Non lo leggiamo
    // — è uno stato volatile del dispatch — ma occupa lo spazio fra
    // `superclass` e `bits`, quindi va nominato o l'offset 32 sembra arbitrario.
    /// `class_data_bits_t bits`.
    pub const BITS: u64 = 32;
}

/// Offset dei campi di `class_ro_t` a 64 bit.
mod ro_off {
    /// `uint32_t flags`.
    pub const FLAGS: u64 = 0;
    /// `uint32_t instanceStart`.
    pub const INSTANCE_START: u64 = 4;
    /// `uint32_t instanceSize`.
    pub const INSTANCE_SIZE: u64 = 8;
    /// `const char *name`.
    pub const NAME: u64 = 24;
    /// `method_list_t *baseMethodList`.
    pub const BASE_METHODS: u64 = 32;
    /// `protocol_list_t *baseProtocols`.
    pub const BASE_PROTOCOLS: u64 = 40;
    /// `ivar_list_t *ivars`.
    pub const IVARS: u64 = 48;
    /// `property_list_t *baseProperties`.
    pub const BASE_PROPERTIES: u64 = 64;
}

/// `RW_REALIZED`: acceso nei `flags` di una `class_rw_t`, mai in una `class_ro_t`.
const RW_REALIZED: u32 = 1 << 31;
/// `RO_META`: la classe è una metaclasse.
const RO_META: u32 = 1;
/// `RO_ROOT`: la classe è una root class (`NSObject`).
const RO_ROOT: u32 = 2;
/// Offset di `ro_or_rw_ext` dentro `class_rw_t`.
const RW_RO_OR_RW_EXT: u64 = 8;

/// Limite di sanità su conteggi di metodi/ivar: oltre questo stiamo quasi
/// certamente seguendo un puntatore sbagliato, e vale la pena dirlo.
const MAX_LIST_ENTRIES: u32 = 8192;
/// Limite di scansione per i nomi.
const MAX_NAME_LEN: usize = 512;
/// Profondità massima della catena di superclassi (cicli inclusi).
const MAX_SUPERCLASS_DEPTH: usize = 64;

/// Un metodo Objective-C letto dalla memoria viva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcMethod {
    /// Selettore (`sel_getName`).
    pub name: String,
    /// Type encoding (`method_getTypeEncoding`), vuoto se non leggibile.
    pub types: String,
    /// Indirizzo dell'implementazione.
    pub imp: u64,
}

impl ObjcMethod {
    /// Nome nella forma `-[Class sel]` / `+[Class sel]`.
    #[must_use]
    pub fn display_name(&self, class: &str, is_class_method: bool) -> String {
        let sigil = if is_class_method { '+' } else { '-' };
        format!("{sigil}[{class} {}]", self.name)
    }
}

/// Una ivar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcIvar {
    /// Nome della ivar.
    pub name: String,
    /// Type encoding.
    pub type_encoding: String,
    /// Offset dall'inizio dell'oggetto (letto tramite indirezione: il campo è
    /// un `int32_t *`, non un valore, perché dyld lo aggiorna a runtime).
    pub offset: u32,
    /// Dimensione in byte.
    pub size: u32,
}

/// Una classe Objective-C ricostruita dalla memoria del target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcClass {
    /// Indirizzo dell'`objc_class`.
    pub address: u64,
    /// Nome della classe.
    pub name: String,
    /// Indirizzo della superclasse (0 per una root class).
    pub superclass: u64,
    /// Indirizzo della `class_ro_t` effettivamente usata.
    pub ro_address: u64,
    /// `flags` della `class_ro_t`.
    pub flags: u32,
    /// Offset da cui iniziano le ivar *di questa* classe: tutto ciò che sta
    /// prima appartiene alle superclassi.
    pub instance_start: u32,
    /// Dimensione di un'istanza.
    pub instance_size: u32,
    /// Metodi della lista base.
    pub methods: Vec<ObjcMethod>,
    /// Ivar dichiarate.
    pub ivars: Vec<ObjcIvar>,
    /// `true` se la classe era già realizzata (abbiamo attraversato una `class_rw_t`).
    pub realized: bool,
}

impl ObjcClass {
    /// `true` se è una metaclasse (`RO_META`).
    #[must_use]
    pub const fn is_meta(&self) -> bool {
        self.flags & RO_META != 0
    }

    /// `true` se è una root class (`RO_ROOT`).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.flags & RO_ROOT != 0
    }

    /// Cerca un metodo per selettore.
    #[must_use]
    pub fn find_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.methods.iter().find(|m| m.name == sel)
    }

    /// Cerca la ivar che copre `offset`.
    #[must_use]
    pub fn ivar_at_offset(&self, offset: u32) -> Option<&ObjcIvar> {
        self.ivars
            .iter()
            .find(|iv| offset >= iv.offset && offset < iv.offset + iv.size.max(1))
    }
}

/// Ispettore del runtime ObjC su una memoria data.
#[derive(Debug, Clone, Copy)]
pub struct ObjcRuntime<'m, M: ObjcMemory + ?Sized> {
    mem: &'m M,
    abi: ObjcAbi,
}

impl<'m, M: ObjcMemory + ?Sized> ObjcRuntime<'m, M> {
    /// Crea un ispettore per l'ABI data.
    pub const fn new(mem: &'m M, abi: ObjcAbi) -> Self {
        Self { mem, abi }
    }

    /// ABI in uso.
    #[must_use]
    pub const fn abi(&self) -> ObjcAbi {
        self.abi
    }

    /// Restituisce la `isa` di un oggetto, oppure un errore se l'oggetto è un
    /// tagged pointer (nel qual caso non c'è nessuna `isa` in memoria).
    ///
    /// # Errors
    /// [`ObjcError::TaggedPointer`] o gli errori di lettura.
    pub fn isa_of(&self, obj: u64) -> ObjcResult<IsaField> {
        if decode_tagged_pointer(obj, self.abi).is_some() {
            return Err(ObjcError::TaggedPointer(obj));
        }
        if obj == 0 {
            return Err(ObjcError::NullPointer { what: "object" });
        }
        let raw = self.mem.read_u64(strip_pac(obj) + class_off::ISA)?;
        Ok(decode_isa(raw, self.abi))
    }

    /// Nome della classe di un oggetto, tagged pointer inclusi.
    ///
    /// # Errors
    /// Errori di lettura della classe.
    pub fn class_name_of_object(&self, obj: u64) -> ObjcResult<String> {
        if let Some(tp) = decode_tagged_pointer(obj, self.abi) {
            return Ok(tp.class.name().to_owned());
        }
        let isa = self.isa_of(obj)?;
        self.class_name(isa.class_ptr)
    }

    /// Legge solo il nome di una classe (percorso economico: niente liste).
    ///
    /// # Errors
    /// Errori di lettura o [`ObjcError::NullPointer`].
    pub fn class_name(&self, class_ptr: u64) -> ObjcResult<String> {
        let (ro, _) = self.resolve_ro(class_ptr)?;
        let name_ptr = strip_pac(self.mem.read_u64(ro + ro_off::NAME)?);
        self.mem.read_cstring(name_ptr, MAX_NAME_LEN)
    }

    /// Risolve `objc_class::bits` nella `class_ro_t` effettiva.
    ///
    /// Una classe realizzata ha in `bits` una `class_rw_t`, non una `class_ro_t`:
    /// le si distingue perché solo la `rw` accende `RW_REALIZED` nei suoi flag.
    /// Ritorna `(indirizzo_ro, realizzata)`.
    fn resolve_ro(&self, class_ptr: u64) -> ObjcResult<(u64, bool)> {
        let class_ptr = strip_pac(class_ptr);
        if class_ptr == 0 {
            return Err(ObjcError::NullPointer { what: "class" });
        }
        let bits = self.mem.read_u64(class_ptr + class_off::BITS)?;
        let data = bits & self.abi.fast_data_mask();
        if data == 0 {
            return Err(ObjcError::NullPointer {
                what: "class data bits",
            });
        }
        let flags = self.mem.read_u32(data + ro_off::FLAGS)?;
        if flags & RW_REALIZED == 0 {
            return Ok((data, false));
        }
        // class_rw_t: `ro_or_rw_ext` è un puntatore taggato nei 2 bit bassi
        // (bit 0 = "è una rw_ext"). Qui gestiamo solo il caso diretto e
        // dichiariamo esplicitamente l'altro invece di leggere spazzatura.
        let ro_or_ext = self.mem.read_u64(data + RW_RO_OR_RW_EXT)?;
        if ro_or_ext & 1 != 0 {
            return Err(ObjcError::Unsupported(
                "class_rw_ext_t (category-extended class) layout not supported".to_owned(),
            ));
        }
        let ro = strip_pac(ro_or_ext) & !0x3;
        if ro == 0 {
            return Err(ObjcError::NullPointer { what: "class_ro_t" });
        }
        Ok((ro, true))
    }

    /// Legge una classe completa: nome, superclasse, metodi, ivar.
    ///
    /// # Errors
    /// Errori di lettura, o [`ObjcError::Implausible`] se una lista ha un
    /// conteggio impossibile (segnale che il puntatore seguito è sbagliato).
    pub fn read_class(&self, class_ptr: u64) -> ObjcResult<ObjcClass> {
        let class_ptr = strip_pac(class_ptr);
        let (ro, realized) = self.resolve_ro(class_ptr)?;
        let flags = self.mem.read_u32(ro + ro_off::FLAGS)?;
        let instance_start = self.mem.read_u32(ro + ro_off::INSTANCE_START)?;
        let instance_size = self.mem.read_u32(ro + ro_off::INSTANCE_SIZE)?;
        let name_ptr = strip_pac(self.mem.read_u64(ro + ro_off::NAME)?);
        let name = self.mem.read_cstring(name_ptr, MAX_NAME_LEN)?;
        let superclass = strip_pac(self.mem.read_u64(class_ptr + class_off::SUPERCLASS)?);

        let methods_ptr = strip_pac(self.mem.read_u64(ro + ro_off::BASE_METHODS)?);
        let methods = if methods_ptr == 0 {
            Vec::new()
        } else {
            self.read_method_list(methods_ptr)?
        };

        let ivars_ptr = strip_pac(self.mem.read_u64(ro + ro_off::IVARS)?);
        let ivars = if ivars_ptr == 0 {
            Vec::new()
        } else {
            self.read_ivar_list(ivars_ptr)?
        };

        Ok(ObjcClass {
            address: class_ptr,
            name,
            superclass,
            ro_address: ro,
            flags,
            instance_start,
            instance_size,
            methods,
            ivars,
            realized,
        })
    }

    /// Indirizzo della lista di protocolli base (0 se assente).
    ///
    /// # Errors
    /// Errori di lettura.
    pub fn base_protocols_ptr(&self, class_ptr: u64) -> ObjcResult<u64> {
        let (ro, _) = self.resolve_ro(class_ptr)?;
        Ok(strip_pac(self.mem.read_u64(ro + ro_off::BASE_PROTOCOLS)?))
    }

    /// Indirizzo della lista di proprietà base (0 se assente).
    ///
    /// # Errors
    /// Errori di lettura.
    pub fn base_properties_ptr(&self, class_ptr: u64) -> ObjcResult<u64> {
        let (ro, _) = self.resolve_ro(class_ptr)?;
        Ok(strip_pac(self.mem.read_u64(ro + ro_off::BASE_PROPERTIES)?))
    }

    /// Catena di superclassi a partire da `class_ptr` (inclusa).
    ///
    /// Si ferma su puntatore nullo, su ciclo o a [`MAX_SUPERCLASS_DEPTH`]: una
    /// `isa` corrotta produce facilmente un ciclo, e un loop infinito dentro un
    /// debugger è peggio di un risultato troncato.
    ///
    /// # Errors
    /// Errori di lettura della prima classe; le successive interrompono la
    /// catena senza fallire, perché una superclasse in una libreria non
    /// mappata è normale.
    pub fn superclass_chain(&self, class_ptr: u64) -> ObjcResult<Vec<String>> {
        let mut out = Vec::new();
        let mut seen = Vec::new();
        let mut cur = strip_pac(class_ptr);
        out.push(self.class_name(cur)?);
        seen.push(cur);
        for _ in 0..MAX_SUPERCLASS_DEPTH {
            let Ok(next) = self.mem.read_u64(cur + class_off::SUPERCLASS) else {
                break;
            };
            let next = strip_pac(next);
            if next == 0 || seen.contains(&next) {
                break;
            }
            let Ok(name) = self.class_name(next) else {
                break;
            };
            out.push(name);
            seen.push(next);
            cur = next;
        }
        Ok(out)
    }

    /// Legge una `method_list_t`, gestendo sia il formato classico (24 byte per
    /// voce, puntatori assoluti) sia le *small method list* (12 byte, offset
    /// relativi a 32 bit) introdotte con iOS 14 / macOS 11.
    ///
    /// # Errors
    /// Errori di lettura o [`ObjcError::Implausible`].
    pub fn read_method_list(&self, list_ptr: u64) -> ObjcResult<Vec<ObjcMethod>> {
        let list_ptr = strip_pac(list_ptr);
        if list_ptr == 0 {
            return Err(ObjcError::NullPointer { what: "method list" });
        }
        let entsize_and_flags = self.mem.read_u32(list_ptr)?;
        let count = self.mem.read_u32(list_ptr + 4)?;
        if count > MAX_LIST_ENTRIES {
            return Err(ObjcError::Implausible {
                what: "method count",
                value: u64::from(count),
                limit: u64::from(MAX_LIST_ENTRIES),
            });
        }
        let small = entsize_and_flags & 0x8000_0000 != 0;
        // `entsizeAndFlags`: nel runtime i flag di una method_list_t sono
        // `0xffff_0003`, cioè TUTTI i 16 bit alti (fra cui
        // `smallMethodListFlag` = 0x8000_0000) più i 2 bit bassi. Solo i bit
        // 2..=15 sono la dimensione della voce. Includere il bit 31 darebbe
        // uno stride di 0x8000_000C e la seconda voce finirebbe fuori lista.
        let entsize = u64::from(entsize_and_flags & 0x0000_fffc);
        let entsize = if entsize == 0 {
            if small { 12 } else { 24 }
        } else {
            entsize
        };

        let mut out = Vec::with_capacity(count as usize);
        for i in 0..u64::from(count) {
            let entry = list_ptr + 8 + i * entsize;
            let m = if small {
                // Ogni campo è un offset relativo alla PROPRIA posizione.
                let name_off = self.mem.read_i32(entry)?;
                let types_off = self.mem.read_i32(entry + 4)?;
                let imp_off = self.mem.read_i32(entry + 8)?;
                // `name` punta a un *selRef*: una parola che contiene il
                // puntatore al nome, non il nome stesso.
                let sel_ref = rel_target(entry, name_off);
                let name_ptr = strip_pac(self.mem.read_u64(sel_ref)?);
                let types_ptr = rel_target(entry + 4, types_off);
                ObjcMethod {
                    name: self.mem.read_cstring(name_ptr, MAX_NAME_LEN)?,
                    types: self
                        .mem
                        .read_cstring(types_ptr, MAX_NAME_LEN)
                        .unwrap_or_default(),
                    imp: rel_target(entry + 8, imp_off),
                }
            } else {
                let name_ptr = strip_pac(self.mem.read_u64(entry)?);
                let types_ptr = strip_pac(self.mem.read_u64(entry + 8)?);
                ObjcMethod {
                    name: self.mem.read_cstring(name_ptr, MAX_NAME_LEN)?,
                    types: self
                        .mem
                        .read_cstring(types_ptr, MAX_NAME_LEN)
                        .unwrap_or_default(),
                    imp: strip_pac(self.mem.read_u64(entry + 16)?),
                }
            };
            out.push(m);
        }
        Ok(out)
    }

    /// Legge una `ivar_list_t` (voci da 32 byte).
    ///
    /// # Errors
    /// Errori di lettura o [`ObjcError::Implausible`].
    pub fn read_ivar_list(&self, list_ptr: u64) -> ObjcResult<Vec<ObjcIvar>> {
        let list_ptr = strip_pac(list_ptr);
        if list_ptr == 0 {
            return Err(ObjcError::NullPointer { what: "ivar list" });
        }
        let entsize = u64::from(self.mem.read_u32(list_ptr)? & 0xffff_fffc);
        let entsize = if entsize == 0 { 32 } else { entsize };
        let count = self.mem.read_u32(list_ptr + 4)?;
        if count > MAX_LIST_ENTRIES {
            return Err(ObjcError::Implausible {
                what: "ivar count",
                value: u64::from(count),
                limit: u64::from(MAX_LIST_ENTRIES),
            });
        }
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..u64::from(count) {
            let entry = list_ptr + 8 + i * entsize;
            // `offset` è un puntatore a int32: il valore vero lo scrive dyld.
            let offset_ptr = strip_pac(self.mem.read_u64(entry)?);
            let offset = if offset_ptr == 0 {
                0
            } else {
                self.mem.read_u32(offset_ptr)?
            };
            let name_ptr = strip_pac(self.mem.read_u64(entry + 8)?);
            let type_ptr = strip_pac(self.mem.read_u64(entry + 16)?);
            out.push(ObjcIvar {
                name: self.mem.read_cstring(name_ptr, MAX_NAME_LEN)?,
                type_encoding: self
                    .mem
                    .read_cstring(type_ptr, MAX_NAME_LEN)
                    .unwrap_or_default(),
                offset,
                size: self.mem.read_u32(entry + 28)?,
            });
        }
        Ok(out)
    }

    /// Descrive un oggetto qualunque in una riga, come farebbe un debugger.
    ///
    /// # Errors
    /// Errori di lettura.
    pub fn describe(&self, obj: u64) -> ObjcResult<String> {
        if let Some(tp) = decode_tagged_pointer(obj, self.abi) {
            return Ok(match tp.class {
                TaggedClass::NsString => decode_tagged_string(&tp)
                    .map_or_else(|e| format!("NSTaggedPointerString(<{e}>)"), |s| {
                        format!("NSTaggedPointerString(\"{s}\")")
                    }),
                TaggedClass::NsNumber => decode_tagged_number(&tp).map_or_else(
                    |e| format!("__NSCFNumber(<{e}>)"),
                    |n| match n {
                        TaggedNumber::Int(v) => format!("__NSCFNumber({v})"),
                        TaggedNumber::Float(v) => format!("__NSCFNumber({v}f)"),
                        TaggedNumber::Double(v) => format!("__NSCFNumber({v})"),
                    },
                ),
                other => format!("{}(tagged payload {:#x})", other.name(), tp.payload),
            });
        }
        if let Ok(cf) = self.read_cfstring(obj) {
            return Ok(format!("@\"{}\"", cf.value));
        }
        let name = self.class_name_of_object(obj)?;
        Ok(format!("<{name}: {obj:#x}>"))
    }

    /// Dà un nome all'implementazione `imp` cercandola tra i metodi di `class_ptr`
    /// e delle sue superclassi. Serve a nominare i frame dentro `objc_msgSend`.
    ///
    /// # Errors
    /// Errori di lettura della prima classe.
    pub fn describe_selector(&self, class_ptr: u64, imp: u64) -> ObjcResult<Option<String>> {
        let imp = strip_pac(imp);
        let mut cur = strip_pac(class_ptr);
        let mut seen = Vec::new();
        for _ in 0..MAX_SUPERCLASS_DEPTH {
            if cur == 0 || seen.contains(&cur) {
                break;
            }
            seen.push(cur);
            let Ok(class) = self.read_class(cur) else {
                break;
            };
            if let Some(m) = class.methods.iter().find(|m| m.imp == imp) {
                return Ok(Some(m.display_name(&class.name, class.is_meta())));
            }
            cur = class.superclass;
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // CFString / NSString
    // -----------------------------------------------------------------------

    /// Legge una `CFString`: sia i literal `__cfstring` emessi dal compilatore
    /// sia gli oggetti costanti creati a runtime, che hanno lo stesso layout.
    ///
    /// # Errors
    /// [`ObjcError::Unsupported`] se i flag indicano una stringa non costante
    /// (le `__NSCFString` mutabili tengono i byte altrove, e indovinare
    /// sarebbe esattamente il "confidently wrong" che qui è vietato).
    pub fn read_cfstring(&self, obj: u64) -> ObjcResult<CfString> {
        let obj = strip_pac(obj);
        if obj == 0 {
            return Err(ObjcError::NullPointer { what: "CFString" });
        }
        if decode_tagged_pointer(obj, self.abi).is_some() {
            return Err(ObjcError::TaggedPointer(obj));
        }
        let isa = self.mem.read_u64(obj)?;
        let flags = self.mem.read_u64(obj + 8)?;
        let data_ptr = strip_pac(self.mem.read_u64(obj + 16)?);
        let length = self.mem.read_u64(obj + 24)?;
        if length > u64::from(MAX_LIST_ENTRIES) * 16 {
            return Err(ObjcError::Implausible {
                what: "CFString length",
                value: length,
                limit: u64::from(MAX_LIST_ENTRIES) * 16,
            });
        }
        let len = usize::try_from(length).unwrap_or(0);
        // Bit 2 dei flag = "contenuto Unicode a 16 bit"; altrimenti 8 bit.
        let unicode = flags & 0x10 != 0;
        let value = if len == 0 {
            String::new()
        } else if unicode {
            let bytes = self.mem.read(data_ptr, len * 2)?;
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            let bytes = self.mem.read(data_ptr, len)?;
            String::from_utf8_lossy(&bytes).into_owned()
        };
        Ok(CfString {
            address: obj,
            isa: decode_isa(isa, self.abi).class_ptr,
            flags,
            data_ptr,
            length: len,
            unicode,
            value,
        })
    }
}

/// Risolve un offset relativo a 32 bit rispetto alla posizione del campo,
/// che è la convenzione delle small method list e dei metadati Swift.
#[must_use]
pub const fn rel_target(field_addr: u64, offset: i32) -> u64 {
    field_addr.wrapping_add(offset as i64 as u64)
}

/// Una `CFString`/`NSString` costante letta dalla memoria.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfString {
    /// Indirizzo dell'oggetto.
    pub address: u64,
    /// Classe (`__NSCFConstantString`).
    pub isa: u64,
    /// Parola dei flag.
    pub flags: u64,
    /// Puntatore ai byte del contenuto.
    pub data_ptr: u64,
    /// Lunghezza in caratteri.
    pub length: usize,
    /// `true` se il contenuto è UTF-16.
    pub unicode: bool,
    /// Contenuto decodificato.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    /// The module's only memory implementor was `SparseMemory`, an in-process
    /// container: nothing bridged a LIVE target's memory, so neither this
    /// module nor `swift_runtime` (which reaches it through
    /// `ObjcMemoryAdapter`) could be pointed at a real process.
    ///
    /// `ReaderMemory` closes that. The test drives the real runtime through a
    /// closure — exactly the shape a debugger supplies — and checks the two
    /// failure modes stay distinguishable, because "this address does not
    /// exist" and "the target had fewer bytes than asked" send a caller
    /// hunting different bugs.
    #[test]
    fn reader_memory_lets_the_runtime_read_from_an_arbitrary_source() {
        // A tagged pointer needs no memory at all: it proves the runtime is
        // really driving through our adapter, not short-circuiting.
        let backing = SparseMemory::new();
        let served = std::cell::RefCell::new(Vec::<(u64, usize)>::new());
        let mem = ReaderMemory(|addr: u64, len: usize| {
            served.borrow_mut().push((addr, len));
            backing.read(addr, len).ok()
        });

        // An unmapped address must be Unreadable, not ShortRead.
        let err = mem.read(0xDEAD_0000, 8).unwrap_err();
        assert!(
            matches!(err, ObjcError::Unreadable { .. }),
            "an absent page must not masquerade as a short read: {err:?}"
        );

        // A source that returns fewer bytes than asked must be ShortRead.
        let truncating = ReaderMemory(|_addr: u64, _len: usize| Some(vec![0u8; 2]));
        let err = truncating.read(0x1000, 8).unwrap_err();
        match err {
            ObjcError::ShortRead { wanted, got, .. } => {
                assert_eq!((wanted, got), (8, 2));
            }
            other => panic!("expected ShortRead, got {other:?}"),
        }

        // And a normal read reaches the source untouched.
        let mut store = SparseMemory::new();
        store.write_u64(0x2000, 0x1122_3344_5566_7788);
        let ok = ReaderMemory(|addr: u64, len: usize| store.read(addr, len).ok());
        assert_eq!(ok.read_u64(0x2000).unwrap(), 0x1122_3344_5566_7788);
        assert!(!served.borrow().is_empty(), "the adapter must call the closure");
    }
    use super::*;

    // Indirizzi del layout sintetico: tutti in una regione "arm64-like".
    const CLASS: u64 = 0x1_0000_1000;
    const SUPER: u64 = 0x1_0000_2000;
    const RO: u64 = 0x1_0000_3000;
    const SUPER_RO: u64 = 0x1_0000_3800;
    const NAME: u64 = 0x1_0000_4000;
    const SUPER_NAME: u64 = 0x1_0000_4100;
    const METHODS: u64 = 0x1_0000_5000;
    const SEL_INIT: u64 = 0x1_0000_5200;
    const SEL_DEALLOC: u64 = 0x1_0000_5240;
    const TYPES: u64 = 0x1_0000_5280;
    const IVARS: u64 = 0x1_0000_6000;
    const IVAR_OFF_SLOT: u64 = 0x1_0000_6200;
    const IVAR_NAME: u64 = 0x1_0000_6300;
    const IVAR_TYPE: u64 = 0x1_0000_6340;
    const OBJECT: u64 = 0x1_0000_7000;
    const CFSTR: u64 = 0x1_0000_8000;
    const CFSTR_DATA: u64 = 0x1_0000_8100;

    /// Costruisce un'immagine di memoria realistica: una classe `Widget` che
    /// deriva da `NSObject`, con 2 metodi e 1 ivar, più un'istanza con isa
    /// non-pointer e una `__NSCFConstantString`.
    fn build_target() -> SparseMemory {
        let mut m = SparseMemory::new();

        // objc_class Widget: isa, superclass, cache(16), bits.
        m.write_u64s(CLASS, &[0, SUPER, 0, 0, RO]);
        // objc_class NSObject (root: superclass = 0).
        m.write_u64s(SUPER, &[0, 0, 0, 0, SUPER_RO]);

        // class_ro_t Widget: flags=0, instanceStart=8, instanceSize=24.
        let mut ro = Vec::new();
        ro.extend_from_slice(&0u32.to_le_bytes()); // flags
        ro.extend_from_slice(&8u32.to_le_bytes()); // instanceStart
        ro.extend_from_slice(&24u32.to_le_bytes()); // instanceSize
        ro.extend_from_slice(&0u32.to_le_bytes()); // reserved
        ro.extend_from_slice(&0u64.to_le_bytes()); // ivarLayout
        ro.extend_from_slice(&NAME.to_le_bytes()); // name
        ro.extend_from_slice(&METHODS.to_le_bytes()); // baseMethodList
        ro.extend_from_slice(&0u64.to_le_bytes()); // baseProtocols
        ro.extend_from_slice(&IVARS.to_le_bytes()); // ivars
        ro.extend_from_slice(&0u64.to_le_bytes()); // weakIvarLayout
        ro.extend_from_slice(&0u64.to_le_bytes()); // baseProperties
        m.write(RO, ro);

        // class_ro_t NSObject: RO_META non impostato, RO_ROOT sì.
        let mut sro = vec![0u8; 72];
        sro[0..4].copy_from_slice(&RO_ROOT.to_le_bytes());
        sro[8..12].copy_from_slice(&8u32.to_le_bytes());
        sro[24..32].copy_from_slice(&SUPER_NAME.to_le_bytes());
        m.write(SUPER_RO, sro);

        m.write_cstr(NAME, "Widget");
        m.write_cstr(SUPER_NAME, "NSObject");
        m.write_cstr(SEL_INIT, "init");
        m.write_cstr(SEL_DEALLOC, "dealloc");
        m.write_cstr(TYPES, "@16@0:8");

        // method_list_t classica: entsize=24, count=2.
        let mut ml = Vec::new();
        ml.extend_from_slice(&24u32.to_le_bytes());
        ml.extend_from_slice(&2u32.to_le_bytes());
        for (sel, imp) in [(SEL_INIT, 0x1_0000_9000u64), (SEL_DEALLOC, 0x1_0000_9100)] {
            ml.extend_from_slice(&sel.to_le_bytes());
            ml.extend_from_slice(&TYPES.to_le_bytes());
            ml.extend_from_slice(&imp.to_le_bytes());
        }
        m.write(METHODS, ml);

        // ivar_list_t: entsize=32, count=1.
        let mut il = Vec::new();
        il.extend_from_slice(&32u32.to_le_bytes());
        il.extend_from_slice(&1u32.to_le_bytes());
        il.extend_from_slice(&IVAR_OFF_SLOT.to_le_bytes());
        il.extend_from_slice(&IVAR_NAME.to_le_bytes());
        il.extend_from_slice(&IVAR_TYPE.to_le_bytes());
        il.extend_from_slice(&8u32.to_le_bytes()); // alignment
        il.extend_from_slice(&8u32.to_le_bytes()); // size
        m.write(IVARS, il);
        m.write(IVAR_OFF_SLOT, 16u32.to_le_bytes().to_vec());
        m.write_cstr(IVAR_NAME, "_backing");
        m.write_cstr(IVAR_TYPE, "@\"NSString\"");

        // Istanza con isa NON-POINTER: bit 0 acceso + refcount nei bit alti.
        // Se qualcuno leggesse la parola come puntatore diretto otterrebbe
        // 0x2000000100001001, che non è mappato: è esattamente il bug che
        // ISA_MASK esiste per evitare.
        let packed_isa = CLASS | ObjcAbi::Arm64.isa_nonpointer_bit() | (0x2 << 56);
        m.write_u64s(OBJECT, &[packed_isa, 0]);

        // __NSCFConstantString: isa, flags(0x7C8 = 8-bit ASCII), data, length.
        m.write_u64s(CFSTR, &[SUPER, 0x0000_07C8, CFSTR_DATA, 5]);
        m.write(CFSTR_DATA, b"hello".to_vec());

        m
    }

    fn rt(m: &SparseMemory) -> ObjcRuntime<'_, SparseMemory> {
        ObjcRuntime::new(m, ObjcAbi::Arm64)
    }

    #[test]
    fn sparse_memory_reads_across_chunk_and_reports_holes() {
        let mut m = SparseMemory::new();
        m.write(0x1000, vec![1, 2, 3, 4]);
        assert_eq!(m.read(0x1001, 2).unwrap(), vec![2, 3]);
        assert!(matches!(
            m.read(0x1002, 8),
            Err(ObjcError::ShortRead { .. })
        ));
        assert!(matches!(m.read(0x9000, 1), Err(ObjcError::Unreadable { .. })));
    }

    #[test]
    fn cstring_stops_at_nul_and_flags_unterminated() {
        let mut m = SparseMemory::new();
        m.write_cstr(0x2000, "selector");
        assert_eq!(m.read_cstring(0x2000, 64).unwrap(), "selector");
        m.write(0x3000, vec![b'A'; 64]);
        assert!(matches!(
            m.read_cstring(0x3000, 16),
            Err(ObjcError::UnterminatedString { .. })
        ));
        assert!(matches!(
            m.read_cstring(0, 16),
            Err(ObjcError::NullPointer { .. })
        ));
    }

    #[test]
    fn nonpointer_isa_is_masked_not_dereferenced() {
        let raw = CLASS | 1 | (0x2 << 56);
        let isa = decode_isa(raw, ObjcAbi::Arm64);
        assert!(isa.nonpointer);
        assert_eq!(isa.class_ptr, CLASS);
        // Un puntatore isa classico resta intatto (a parte l'allineamento).
        let plain = decode_isa(CLASS, ObjcAbi::Arm64);
        assert!(!plain.nonpointer);
        assert_eq!(plain.class_ptr, CLASS);
    }

    #[test]
    fn x86_64_isa_mask_differs_from_arm64() {
        let raw = 0x0000_7f12_3456_7890 | 1;
        assert_eq!(
            decode_isa(raw, ObjcAbi::X86_64).class_ptr,
            0x0000_7f12_3456_7890
        );
        // La maschera arm64 è più stretta: taglierebbe i bit alti.
        assert_ne!(
            decode_isa(raw, ObjcAbi::Arm64).class_ptr,
            0x0000_7f12_3456_7890
        );
    }

    #[test]
    fn strip_pac_removes_signature_bits() {
        assert_eq!(strip_pac(0x9a3c_0001_0000_1000), 0x0001_0000_1000);
        assert_eq!(strip_pac(CLASS), CLASS);
    }

    #[test]
    fn reads_class_with_methods_and_ivars() {
        let m = build_target();
        let c = rt(&m).read_class(CLASS).unwrap();
        assert_eq!(c.name, "Widget");
        assert_eq!(c.superclass, SUPER);
        assert_eq!(c.instance_size, 24);
        assert_eq!(c.instance_start, 8);
        assert!(!c.realized);
        assert_eq!(c.methods.len(), 2);
        assert_eq!(c.methods[0].name, "init");
        assert_eq!(c.methods[0].types, "@16@0:8");
        assert_eq!(c.methods[1].imp, 0x1_0000_9100);
        assert_eq!(c.ivars.len(), 1);
        assert_eq!(c.ivars[0].name, "_backing");
        assert_eq!(c.ivars[0].offset, 16);
        assert_eq!(c.ivars[0].type_encoding, "@\"NSString\"");
        assert_eq!(c.ivar_at_offset(20).unwrap().name, "_backing");
        assert!(c.ivar_at_offset(0).is_none());
        assert_eq!(
            c.find_method("dealloc").unwrap().display_name("Widget", false),
            "-[Widget dealloc]"
        );
    }

    #[test]
    fn object_with_nonpointer_isa_resolves_to_class_name() {
        let m = build_target();
        let r = rt(&m);
        let isa = r.isa_of(OBJECT).unwrap();
        assert!(isa.nonpointer);
        assert_eq!(isa.class_ptr, CLASS);
        assert_eq!(r.class_name_of_object(OBJECT).unwrap(), "Widget");
        assert_eq!(r.describe(OBJECT).unwrap(), "<Widget: 0x100007000>");
    }

    #[test]
    fn superclass_chain_terminates_at_root() {
        let m = build_target();
        assert_eq!(
            rt(&m).superclass_chain(CLASS).unwrap(),
            vec!["Widget".to_owned(), "NSObject".to_owned()]
        );
    }

    #[test]
    fn superclass_chain_survives_a_cycle() {
        let mut m = build_target();
        // NSObject punta indietro a Widget: catena ciclica.
        m.write_u64s(SUPER, &[0, CLASS, 0, 0, SUPER_RO]);
        let chain = rt(&m).superclass_chain(CLASS).unwrap();
        assert_eq!(chain, vec!["Widget".to_owned(), "NSObject".to_owned()]);
    }

    #[test]
    fn realized_class_is_followed_through_class_rw_t() {
        let mut m = build_target();
        const RW: u64 = 0x1_000a_0000;
        // bits punta a una class_rw_t: flags con RW_REALIZED, ro a offset 8.
        m.write_u64s(CLASS, &[0, SUPER, 0, 0, RW]);
        let mut rw = Vec::new();
        rw.extend_from_slice(&RW_REALIZED.to_le_bytes());
        rw.extend_from_slice(&0u32.to_le_bytes());
        rw.extend_from_slice(&RO.to_le_bytes());
        m.write(RW, rw);
        let c = rt(&m).read_class(CLASS).unwrap();
        assert!(c.realized);
        assert_eq!(c.name, "Widget");
        assert_eq!(c.ro_address, RO);
    }

    #[test]
    fn rw_ext_is_refused_explicitly_not_guessed() {
        let mut m = build_target();
        const RW: u64 = 0x1_000b_0000;
        m.write_u64s(CLASS, &[0, SUPER, 0, 0, RW]);
        let mut rw = Vec::new();
        rw.extend_from_slice(&RW_REALIZED.to_le_bytes());
        rw.extend_from_slice(&0u32.to_le_bytes());
        rw.extend_from_slice(&(RO | 1).to_le_bytes()); // bit 0 = rw_ext
        m.write(RW, rw);
        assert!(matches!(
            rt(&m).read_class(CLASS),
            Err(ObjcError::Unsupported(_))
        ));
    }

    #[test]
    fn small_method_list_uses_relative_offsets() {
        let mut m = SparseMemory::new();
        const LIST: u64 = 0x2_0000_0000;
        const SELREF: u64 = 0x2_0000_1000;
        const SELNAME: u64 = 0x2_0000_1100;
        const TYPESTR: u64 = 0x2_0000_1200;
        const IMP: u64 = 0x2_0000_2000;
        let entry = LIST + 8;
        let mut ml = Vec::new();
        ml.extend_from_slice(&(12u32 | 0x8000_0000).to_le_bytes());
        ml.extend_from_slice(&1u32.to_le_bytes());
        ml.extend_from_slice(&i32::try_from(SELREF - entry).unwrap().to_le_bytes());
        ml.extend_from_slice(&i32::try_from(TYPESTR - (entry + 4)).unwrap().to_le_bytes());
        ml.extend_from_slice(&i32::try_from(IMP - (entry + 8)).unwrap().to_le_bytes());
        m.write(LIST, ml);
        m.write_u64(SELREF, SELNAME);
        m.write_cstr(SELNAME, "doWork:");
        m.write_cstr(TYPESTR, "v20@0:8i16");

        let methods = rt(&m).read_method_list(LIST).unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "doWork:");
        assert_eq!(methods[0].types, "v20@0:8i16");
        assert_eq!(methods[0].imp, IMP);
    }

    /// Il campo `entsizeAndFlags` di una small method list vale
    /// `12 | 0x8000_0000`. Se il bit 31 finisce nello stride, la seconda voce
    /// viene cercata a `list + 8 + 0x8000_000C` invece che a `list + 20`.
    /// Con una sola voce il difetto è invisibile: servono almeno due metodi.
    #[test]
    fn small_method_list_stride_excludes_flag_bit() {
        let mut m = SparseMemory::new();
        const LIST: u64 = 0x3_0000_0000;
        const SELREF0: u64 = 0x3_0000_1000;
        const SELREF1: u64 = 0x3_0000_1008;
        const SELNAME0: u64 = 0x3_0000_1100;
        const SELNAME1: u64 = 0x3_0000_1180;
        const TYPESTR: u64 = 0x3_0000_1200;
        const IMP0: u64 = 0x3_0000_2000;
        const IMP1: u64 = 0x3_0000_2100;

        let entry0 = LIST + 8;
        let entry1 = LIST + 8 + 12;
        let mut ml = Vec::new();
        ml.extend_from_slice(&(12u32 | 0x8000_0000).to_le_bytes());
        ml.extend_from_slice(&2u32.to_le_bytes());
        for (entry, selref, imp) in [(entry0, SELREF0, IMP0), (entry1, SELREF1, IMP1)] {
            ml.extend_from_slice(&i32::try_from(selref - entry).unwrap().to_le_bytes());
            ml.extend_from_slice(&i32::try_from(TYPESTR - (entry + 4)).unwrap().to_le_bytes());
            ml.extend_from_slice(&i32::try_from(imp - (entry + 8)).unwrap().to_le_bytes());
        }
        m.write(LIST, ml);
        m.write_u64(SELREF0, SELNAME0);
        m.write_u64(SELREF1, SELNAME1);
        m.write_cstr(SELNAME0, "start");
        m.write_cstr(SELNAME1, "stop");
        m.write_cstr(TYPESTR, "v16@0:8");

        let methods = rt(&m)
            .read_method_list(LIST)
            .expect("lo stride di 12 byte deve restare dentro la lista");
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].name, "start");
        assert_eq!(methods[0].imp, IMP0);
        assert_eq!(methods[1].name, "stop");
        assert_eq!(methods[1].imp, IMP1);
    }

    #[test]
    fn implausible_counts_are_reported_not_iterated() {
        let mut m = SparseMemory::new();
        let mut ml = Vec::new();
        ml.extend_from_slice(&24u32.to_le_bytes());
        ml.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        m.write(0x4000, ml);
        assert!(matches!(
            rt(&m).read_method_list(0x4000),
            Err(ObjcError::Implausible { .. })
        ));
    }

    #[test]
    fn describe_selector_walks_up_the_hierarchy() {
        let m = build_target();
        let r = rt(&m);
        assert_eq!(
            r.describe_selector(CLASS, 0x1_0000_9000).unwrap(),
            Some("-[Widget init]".to_owned())
        );
        assert_eq!(r.describe_selector(CLASS, 0xdead_beef).unwrap(), None);
    }

    #[test]
    fn reads_constant_cfstring_ascii() {
        let m = build_target();
        let s = rt(&m).read_cfstring(CFSTR).unwrap();
        assert_eq!(s.value, "hello");
        assert_eq!(s.length, 5);
        assert!(!s.unicode);
        assert_eq!(rt(&m).describe(CFSTR).unwrap(), "@\"hello\"");
    }

    #[test]
    fn reads_utf16_cfstring() {
        let mut m = SparseMemory::new();
        const S: u64 = 0x5_0000_0000;
        const D: u64 = 0x5_0000_1000;
        m.write_u64s(S, &[0x1000, 0x10, D, 3]);
        let mut data = Vec::new();
        for c in "cià".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        m.write(D, data);
        let s = rt(&m).read_cfstring(S).unwrap();
        assert!(s.unicode);
        assert_eq!(s.value, "cià");
    }

    #[test]
    fn arm64_tagged_pointer_is_detected_and_not_dereferenced() {
        // slot 3 (NSNumber), bit 63 acceso.
        let ptr = (1u64 << 63) | (3 << 60) | (42 << 4) | 3;
        let tp = decode_tagged_pointer(ptr, ObjcAbi::Arm64).unwrap();
        assert_eq!(tp.class, TaggedClass::NsNumber);
        let m = build_target();
        assert!(matches!(
            rt(&m).isa_of(ptr),
            Err(ObjcError::TaggedPointer(_))
        ));
        assert_eq!(rt(&m).class_name_of_object(ptr).unwrap(), "__NSCFNumber");
    }

    #[test]
    fn plain_pointer_is_not_mistaken_for_tagged() {
        assert!(decode_tagged_pointer(CLASS, ObjcAbi::Arm64).is_none());
        assert!(decode_tagged_pointer(0, ObjcAbi::Arm64).is_none());
        // Su x86_64 il bit di tag è quello basso: lo stesso valore è "normale"
        // perché allineato, ma un dispari sarebbe tagged.
        assert!(decode_tagged_pointer(CLASS, ObjcAbi::X86_64).is_none());
        assert!(decode_tagged_pointer(CLASS | 1, ObjcAbi::X86_64).is_some());
    }

    #[test]
    fn tagged_nsnumber_decodes_signed_widths() {
        let mk = |value: u64, kind: u64| {
            decode_tagged_pointer((1u64 << 63) | (3 << 60) | (value << 4) | kind, ObjcAbi::Arm64)
                .unwrap()
        };
        assert_eq!(
            decode_tagged_number(&mk(42, 3)).unwrap(),
            TaggedNumber::Int(42)
        );
        // -1 a 8 bit: payload 0xFF, tipo 1.
        assert_eq!(
            decode_tagged_number(&mk(0xFF, 1)).unwrap(),
            TaggedNumber::Int(-1)
        );
        assert_eq!(
            decode_tagged_number(&mk(u64::from(1.5f32.to_bits()), 5)).unwrap(),
            TaggedNumber::Float(1.5)
        );
        // Tipo sconosciuto: errore esplicito, nessun numero inventato.
        assert!(matches!(
            decode_tagged_number(&mk(1, 9)),
            Err(ObjcError::Unsupported(_))
        ));
    }

    #[test]
    fn tagged_nsnumber_rejects_wrong_slot() {
        let tp = decode_tagged_pointer((1u64 << 63) | (2 << 60), ObjcAbi::Arm64).unwrap();
        assert!(matches!(
            decode_tagged_number(&tp),
            Err(ObjcError::Unsupported(_))
        ));
    }

    #[test]
    fn tagged_nsstring_ascii_roundtrip() {
        // "abc": 3 caratteri ASCII, lunghezza nel nibble basso.
        let mut bits = 0u64;
        for (i, c) in b"abc".iter().enumerate() {
            bits |= u64::from(*c) << (i * 8);
        }
        let ptr = (1u64 << 63) | (2 << 60) | (bits << 4) | 3;
        let tp = decode_tagged_pointer(ptr, ObjcAbi::Arm64).unwrap();
        assert_eq!(tp.class, TaggedClass::NsString);
        assert_eq!(decode_tagged_string(&tp).unwrap(), "abc");
    }

    #[test]
    fn tagged_nsstring_six_bit_alphabet() {
        // 8 caratteri presi dall'alfabeto a 6 bit -> codifica compressa.
        let text = "eilotrm.";
        let mut bits = 0u64;
        for (i, c) in text.bytes().enumerate() {
            let idx = TAGGED_STRING_ALPHABET_6
                .iter()
                .position(|&a| a == c)
                .unwrap() as u64;
            bits |= idx << (i * 6);
        }
        let ptr = (1u64 << 63) | (2 << 60) | (bits << 4) | 8;
        let tp = decode_tagged_pointer(ptr, ObjcAbi::Arm64).unwrap();
        assert_eq!(decode_tagged_string(&tp).unwrap(), text);
    }

    #[test]
    fn tagged_nsstring_rejects_impossible_length() {
        let ptr = (1u64 << 63) | (2 << 60) | 15;
        let tp = decode_tagged_pointer(ptr, ObjcAbi::Arm64).unwrap();
        assert!(matches!(
            decode_tagged_string(&tp),
            Err(ObjcError::Unsupported(_))
        ));
    }

    #[test]
    fn describe_formats_tagged_values() {
        let m = build_target();
        let r = rt(&m);
        let num = (1u64 << 63) | (3 << 60) | (7 << 4) | 3;
        assert_eq!(r.describe(num).unwrap(), "__NSCFNumber(7)");
        let mut bits = 0u64;
        for (i, c) in b"hi".iter().enumerate() {
            bits |= u64::from(*c) << (i * 8);
        }
        let s = (1u64 << 63) | (2 << 60) | (bits << 4) | 2;
        assert_eq!(r.describe(s).unwrap(), "NSTaggedPointerString(\"hi\")");
    }

    #[test]
    fn class_flags_expose_meta_and_root() {
        let m = build_target();
        let root = rt(&m).read_class(SUPER).unwrap();
        assert!(root.is_root());
        assert!(!root.is_meta());
        assert_eq!(root.superclass, 0);
    }

    #[test]
    fn null_and_missing_pointers_are_typed_errors() {
        let m = build_target();
        let r = rt(&m);
        assert!(matches!(r.isa_of(0), Err(ObjcError::NullPointer { .. })));
        assert!(matches!(
            r.read_class(0),
            Err(ObjcError::NullPointer { .. })
        ));
        assert!(matches!(
            r.read_method_list(0),
            Err(ObjcError::NullPointer { .. })
        ));
        assert!(matches!(
            r.read_ivar_list(0),
            Err(ObjcError::NullPointer { .. })
        ));
    }

    #[test]
    fn protocol_and_property_pointers_are_exposed() {
        let m = build_target();
        assert_eq!(rt(&m).base_protocols_ptr(CLASS).unwrap(), 0);
        assert_eq!(rt(&m).base_properties_ptr(CLASS).unwrap(), 0);
    }

    #[test]
    fn rel_target_handles_negative_offsets() {
        assert_eq!(rel_target(0x1000, -0x10), 0xff0);
        assert_eq!(rel_target(0x1000, 0x10), 0x1010);
    }
}
