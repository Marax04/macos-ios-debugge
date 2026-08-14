# rustre-loader-firmware

Crate per il caricamento e l'analisi statica di immagini firmware embedded/IoT. Supporta formati binari raw, Intel HEX, Motorola S-Record, U-Boot legacy e FIT image, UEFI/FV, SquashFS, CramFS, JFFS2, ext2, FAT. Include analisi di entropia, rilevamento di segnature, scanner di sicurezza (credenziali, crypto, interfacce di debug, shell) e generazione di report.

**Dipendenze principali:** `rustre-core`, `async-trait`, `thiserror`, `serde`, `serde_json`

---

## Modulo: `lib.rs` — Rilevamento e loader principali

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `detect_firmware_kind(data)` | `&[u8]` | `FirmwareKind` | Identifica il tipo di firmware (raw, ELF, PE, UBoot, UEFI, IHex, Srec, UF2, ecc.) ispezionando magic bytes e strutture. |
| `scan_embedded_signatures(data)` | `&[u8]` | `Vec<EmbeddedSignature>` | Cerca firme embedded note (kernel, JFFS2, SquashFS, ecc.) nell'intera immagine. |
| `detect_binary_arch(data)` | `&[u8]` | `BinaryArch` | Stima l'architettura CPU del payload (x86, ARM, MIPS, RISC-V, PowerPC…) tramite euristica sui byte. |
| `detect_raw_endian(arch)` | `BinaryArch` | `Option<Endian>` | Restituisce l'endianness tipica per una data architettura. |
| `detect_rtos(data)` | `&[u8]` | `Option<RtosKind>` | Cerca stringhe RTOS noti (FreeRTOS, VxWorks, ThreadX, ecc.) nell'immagine. |
| `detect_arch_hint(data)` | `&[u8]` | `Option<String>` | Ricava un hint testuale sull'architettura da stringhe leggibili nel binario. |
| `detect_endian_hint(data)` | `&[u8]` | `Option<String>` | Ricava un hint sull'endianness da stringhe diagnostiche. |
| `detect_boot_sections(data, base)` | `&[u8]`, `u64` | `Vec<BootSection>` | Identifica sezioni di boot (entry point, reset vector, exception table) nell'immagine. |
| `classify_string(s)` | `&str` | `StringCategory` | Classifica una stringa in categorie (URL, IP, credenziale, path, ecc.). |
| `extract_firmware_strings(data, min_len)` | `&[u8]`, `usize` | `Vec<FirmwareString>` | Estrae stringhe ASCII/UTF-8 stampabili dal binario con lunghezza minima. |

### Struct principali (`lib.rs`)
- `FirmwareLoader` — loader per raw binary firmware
- `IntelHexLoader` — loader per file Intel HEX
- `SrecLoader` — loader per Motorola S-Record
- `Uf2Loader` — loader per Microsoft UF2
- `ByteHistogram` — istogramma a 256 bucket sui byte di un buffer
- `FirmwareInfo` — informazioni aggregate (arch, endian, kind, entry point)
- `BootSection` — sezione di boot rilevata con offset e tipo
- `UBootHeader` / `IntelHexRecord` / `SrecRecord` / `Uf2Record` / `FirmwareString` / `FirmwareArch`

---

## Modulo: `entropy_analysis.rs` — Analisi dell'entropia

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `EntropyClass::from_entropy(e)` | `f64` | `EntropyClass` | Classifica un valore di entropia (Zero, VeryLow, Low, Medium, High, VeryHigh). |
| `EntropyClass::is_high(self)` | — | `bool` | True se la classe è High o VeryHigh. |
| `EntropyClass::label(self)` | — | `&'static str` | Nome testuale della classe. |
| `EntropyClass::typical_entropy(self)` | — | `f64` | Valore di entropia tipico per la classe. |
| `EntropyRegion::end_offset(&self)` | — | `usize` | Fine dell'intervallo di entropia elevata. |
| `EntropyRegion::overlaps(&self, start, end)` | `usize`, `usize` | `bool` | True se la regione si sovrappone a un range dato. |
| `EntropyHeatmap::peak(&self)` | — | `Option<(usize, f64)>` | Offset e valore del picco di entropia. |
| `EntropyHeatmap::trough(&self)` | — | `Option<(usize, f64)>` | Offset e valore del minimo di entropia. |
| `EntropyHeatmap::average(&self)` | — | `f64` | Entropia media su tutti i campioni. |
| `EntropyHeatmap::fraction_above(&self, threshold)` | `f64` | `f64` | Frazione dei campioni sopra una soglia. |
| `EntropyHeatmap::samples_of_class(&self, class)` | `EntropyClass` | `Vec<(usize, f64)>` | Campioni appartenenti a una classe specifica. |
| `EntropyHeatmap::ascii_bar(&self, width)` | `usize` | `String` | Heatmap ASCII-art a larghezza fissa. |
| `EntropyAnalyzer::new(window_size, step_size, min_region_bytes)` | `usize`, `usize`, `usize` | `Self` | Crea un analizzatore configurato. |
| `EntropyAnalyzer::block_entropy(data)` | `&[u8]` | `f64` | Calcola l'entropia di Shannon su un blocco. |
| `EntropyAnalyzer::classify(e)` | `f64` | `EntropyClass` | Classifica un valore di entropia. |
| `EntropyAnalyzer::classify_block(&self, data)` | `&[u8]` | `EntropyClass` | Classifica l'entropia di un blocco. |
| `EntropyAnalyzer::sliding_entropy(&self, data)` | `&[u8]` | `Vec<(usize, f64)>` | Entropia a finestra scorrevole. |
| `EntropyAnalyzer::heatmap(&self, data)` | `&[u8]` | `EntropyHeatmap` | Genera la heatmap completa. |
| `EntropyAnalyzer::find_regions(&self, data)` | `&[u8]` | `Vec<EntropyRegion>` | Trova regioni ad alta entropia (potenzialmente compresse/cifrate). |
| `EntropyAnalyzer::class_distribution(&self, data)` | `&[u8]` | `[usize; 6]` | Distribuzione dei campioni nelle 6 classi. |
| `EntropyAnalyzer::compressed_fraction(&self, data)` | `&[u8]` | `f64` | Frazione del binario ritenuta compressa/cifrata. |
| `EntropyAnalyzer::highest_entropy_offset(&self, data)` | `&[u8]` | `Option<usize>` | Offset del blocco con entropia massima. |
| `EntropyAnalyzer::lowest_entropy_offset(&self, data)` | `&[u8]` | `Option<usize>` | Offset del blocco con entropia minima. |
| `EntropyAnalyzer::is_high_entropy_blob(data)` | `&[u8]` | `bool` | True se la maggior parte del buffer è ad alta entropia. |
| `EntropyReport::analyse(data)` | `&[u8]` | `Self` | Report completo: heatmap + regioni + statistiche. |

---

## Modulo: `srec_parser.rs` — Parser Motorola S-Record

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `SrecType::from_char(c)` | `u8` | `Self` | Converte il carattere tipo ('0'–'9') in enum. |
| `SrecType::to_char(self)` | — | `u8` | Byte ASCII del tipo. |
| `SrecType::addr_bytes(self)` | — | `usize` | Numero di byte dell'indirizzo per questo tipo (2, 3 o 4). |
| `SrecType::is_data(self)` | — | `bool` | True per tipi S1/S2/S3 (dati). |
| `SrecType::is_terminator(self)` | — | `bool` | True per tipi S7/S8/S9. |
| `SrecType::name(self)` | — | `&'static str` | Nome testuale del tipo. |
| `SrecRecord::parse_line(line)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsing di una singola riga SREC, verifica checksum. |
| `SrecRecord::to_srec_string(&self)` | — | `String` | Serializza il record nel formato testuale. |
| `SrecSegment::end_addr(&self)` | — | `u64` | Indirizzo di fine segmento. |
| `SrecSegment::size(&self)` | — | `usize` | Dimensione in byte. |
| `SrecSegment::extend(&mut self, bytes)` | `&[u8]` | `()` | Aggiunge byte al segmento. |
| `SrecImage::parse(data)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsing completo di un file SREC multi-linea. |
| `SrecImage::build_binary_image(&self, base, fill_byte)` | `Option<u64>`, `u8` | `Vec<u8>` | Costruisce l'immagine binaria piatta riempiendo i gap. |
| `SrecImage::total_data_bytes(&self)` | — | `usize` | Byte dati totali in tutti i segmenti. |
| `SrecImage::min_address(&self)` | — | `Option<u64>` | Indirizzo minimo. |
| `SrecImage::max_address(&self)` | — | `Option<u64>` | Indirizzo massimo. |
| `SrecImage::gap_count(&self)` | — | `usize` | Numero di gap tra segmenti. |
| `SrecImage::total_gap_bytes(&self)` | — | `u64` | Byte totali di gap. |
| `SrecImage::effective_entry(&self)` | — | `Option<u64>` | Entry point dal record terminatore. |
| `SrecImage::has_32bit_addresses(&self)` | — | `bool` | True se usa record S3/S7 (indirizzi 32 bit). |
| `encode_to_srec(data, base_address, bytes_per_record)` | `&[u8]`, `u32`, `u8` | `String` | Serializza un buffer binario in testo SREC. |

---

## Modulo: `intel_hex.rs` — Parser Intel HEX

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `IHexRecordType::from_byte(b)` | `u8` | `Self` | Converte il byte tipo in enum (Data, EOF, ExtSeg, StartSeg, ExtLinear, StartLinear). |
| `IHexRecordType::to_byte(self)` | — | `u8` | Byte numerico del tipo. |
| `IHexRecordType::name(self)` | — | `&'static str` | Nome testuale. |
| `IHexRecord::parse_line(line)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsing di una riga HEX, verifica checksum. |
| `IHexRecord::to_hex_string(&self)` | — | `String` | Serializza nel formato textuale Intel HEX. |
| `IHexSegment::end_addr(&self)` | — | `u64` | Indirizzo di fine segmento. |
| `IHexSegment::contains(&self, addr)` | `u64` | `bool` | True se l'indirizzo cade nel segmento. |
| `IHexSegment::extend(&mut self, bytes)` | `&[u8]` | `()` | Aggiunge byte. |
| `IHexSegment::size(&self)` | — | `usize` | Dimensione in byte. |
| `IHexImage::parse(data)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsing completo di un file Intel HEX. |
| `IHexImage::build_binary_image(&self, base, fill_byte)` | `Option<u64>`, `u8` | `Vec<u8>` | Costruisce l'immagine binaria piatta. |
| `IHexImage::min_address(&self)` | — | `Option<u64>` | Indirizzo minimo. |
| `IHexImage::max_address(&self)` | — | `Option<u64>` | Indirizzo massimo. |
| `IHexImage::total_data_bytes(&self)` | — | `usize` | Byte dati totali. |
| `IHexImage::gap_count(&self)` | — | `usize` | Numero di gap. |
| `IHexImage::total_gap_bytes(&self)` | — | `u64` | Byte di gap totali. |
| `IHexImage::entry_point(&self)` | — | `Option<u64>` | Entry point (dal record StartLinear o StartSeg). |
| `ihex_checksum(body)` | `&[u8]` | `u8` | Calcola il checksum a complemento a due di un record. |
| `encode_to_ihex(data, base_address, bytes_per_record)` | `&[u8]`, `u32`, `u8` | `String` | Serializza un buffer binario in testo Intel HEX. |

---

## Modulo: `uboot_parser.rs` — Parser U-Boot / FDT

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `UBootOsType::from_byte(b)` | `u8` | `Self` | Converte il byte OS type in enum. |
| `UBootOsType::as_str(self)` | — | `&'static str` | Nome OS (Linux, VxWorks, FreeBSD, ecc.). |
| `UBootArchType::from_byte(b)` | `u8` | `Self` | Converte il byte arch type in enum. |
| `UBootArchType::as_str(self)` | — | `&'static str` | Nome architettura. |
| `UBootImageType::from_byte(b)` | `u8` | `Self` | Converte il byte image type in enum. |
| `UBootImageType::as_str(self)` | — | `&'static str` | Nome tipo immagine (Standalone, Kernel, Ramdisk, ecc.). |
| `UBootCompressionType::from_byte(b)` | `u8` | `Self` | Converte il byte compression type in enum (None, gzip, bzip2, lzma, ecc.). |
| `UBootCompressionType::as_str(self)` | — | `&'static str` | Nome compressione. |
| `UBootLegacyHeader::parse(data)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsing dell'header U-Boot legacy (magic 0x27051956). |
| `UBootLegacyHeader::payload<'a>(&self, data)` | `&'a [u8]` | `Option<&'a [u8]>` | Slice del payload dopo l'header. |
| `UBootLegacyHeader::total_size(&self)` | — | `usize` | Dimensione totale header + payload. |
| `FdtProperty::as_str(&self)` | — | `Option<&str>` | Valore della proprietà come stringa. |
| `FdtProperty::as_u32_be(&self)` | — | `Option<u32>` | Valore come u32 big-endian. |
| `FdtProperty::as_u64_be(&self)` | — | `Option<u64>` | Valore come u64 big-endian. |
| `FdtNode::prop(&self, name)` | `&str` | `Option<&FdtProperty>` | Cerca una proprietà per nome. |
| `FdtNode::data_prop(&self)` | — | `Option<&[u8]>` | Restituisce la proprietà "data" come slice. |
| `FdtNode::child(&self, name)` | `&str` | `Option<&FdtNode>` | Cerca un figlio per nome. |
| `FdtNode::full_name(&self)` | — | `String` | Nome completo del nodo. |
| `FdtParser::new(data)` | `&'a [u8]` | `Result<Self, FirmwareError>` | Crea il parser FDT (Device Tree Blob) validando il magic. |
| `FdtParser::parse_tree(&self)` | — | `Result<FdtNode, FirmwareError>` | Parsa l'albero FDT completo in struttura ricorsiva. |
| `FitImageBundle::parse(data)` | `&[u8]` | `Result<Self, FirmwareError>` | Parsa un FIT image (Flattened Image Tree) completo. |
| `FitImageBundle::kernel(&self)` | — | `Option<&FitImage>` | Sottoimage kernel. |
| `FitImageBundle::ramdisk(&self)` | — | `Option<&FitImage>` | Sottoimage ramdisk. |
| `FitImageBundle::fdt(&self)` | — | `Option<&FitImage>` | Sottoimage device tree. |
| `UBootImage::parse(data)` | `&[u8]` | `Result<Self, FirmwareError>` | Parser unificato: rileva se FIT o legacy. |
| `UBootImage::is_fit(&self)` | — | `bool` | True se FIT image. |
| `UBootImage::is_legacy(&self)` | — | `bool` | True se legacy header. |
| `UBootImage::entry_point(&self)` | — | `Option<u64>` | Entry point dell'immagine. |
| `UBootImage::load_address(&self)` | — | `Option<u64>` | Indirizzo di caricamento. |

---

## Modulo: `uefi_analysis.rs` — Analisi UEFI/FV

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `format_guid(g)` | `&Guid` | `String` | Formatta un GUID UEFI nel formato standard `{8-4-4-4-12}`. |
| `GuidDatabase::new()` | — | `Self` | Database GUID vuoto. |
| `GuidDatabase::load_standard()` | — | `Self` | Carica il database con i GUID UEFI standard noti. |
| `GuidDatabase::insert(&mut self, guid, name)` | `Guid`, `impl Into<String>` | `()` | Aggiunge una voce al database. |
| `GuidDatabase::lookup(&self, guid)` | `&Guid` | `Option<&str>` | Risolve un GUID in nome simbolico. |
| `GuidDatabase::len(&self)` | — | `usize` | Numero di voci. |
| `GuidDatabase::is_empty(&self)` | — | `bool` | True se vuoto. |
| `FfsFileType::from_u8(v)` | `u8` | `Result<Self, UefiError>` | Converte il byte tipo FFS in enum. |
| `FfsFileType::is_executable(self)` | — | `bool` | True per tipi driver/applicazione. |
| `HiiPackageType::from_u8(v)` | `u8` | `Self` | Converte il byte tipo HII package in enum. |
| `HiiPackageType::is_user_visible(self)` | — | `bool` | True per pacchetti Forms/Strings/Images. |
| `HiiPackage::new(pkg_type, data)` | `HiiPackageType`, `Vec<u8>` | `Self` | Crea un pacchetto HII. |
| `EfiFvHeader::verify_header(hdr_data)` | `&[u8]` | `Self` | Legge e verifica l'header del Firmware Volume (magic `_FVH`). |
| `EfiFvHeader::is_valid(&self)` | — | `bool` | True se il magic e la dimensione sono coerenti. |
| `EfiFfs::new(guid, file_type, size)` | `Guid`, `FfsFileType`, `u32` | `Self` | Crea un descrittore FFS. |
| `EfiFfs::guid_str(&self)` | — | `String` | GUID formattato come stringa. |
| `EfiFfs::find_section(&self, sec_type)` | `EfiSectionType` | `Option<&EfiSection>` | Cerca la prima sezione di un dato tipo. |
| `EfiFfs::has_pe(&self)` | — | `bool` | True se il file contiene una sezione PE. |
| `EfiSectionType::from_u8(v)` | `u8` | `Result<Self, UefiError>` | Converte il byte tipo sezione in enum. |
| `EfiSectionType::is_executable(self)` | — | `bool` | True per sezioni PE32/TE. |
| `EfiSectionType::is_dependency(self)` | — | `bool` | True per sezioni DXE_DEPEX/PEI_DEPEX. |
| `EfiSection::new(section_type, raw_data)` | `EfiSectionType`, `Vec<u8>` | `Self` | Crea una sezione EFI. |
| `EfiFirmwareVolume::parse(data, offset)` | `&[u8]`, `usize` | `Result<Self, UefiError>` | Parsa un Firmware Volume a partire da un offset. |
| `EfiFirmwareVolume::find_file(&self, guid)` | `&Guid` | `Option<&EfiFfs>` | Cerca un file FFS per GUID. |
| `EfiFirmwareVolume::executable_files(&self)` | — | `Vec<&EfiFfs>` | Lista file di tipo eseguibile. |
| `EfiFirmwareVolume::pe_files(&self)` | — | `Vec<&EfiFfs>` | Lista file con sezione PE. |
| `DepexExpression::new()` | — | `Self` | Espressione di dipendenza vuota. |
| `DepexExpression::parse(data)` | `&[u8]` | `Result<Self, UefiError>` | Parsa un bytecode DEPEX. |
| `DepexExpression::referenced_guids(&self)` | — | `Vec<&Guid>` | GUID referenziati nell'espressione. |
| `DepexExpression::is_always_true(&self)` | — | `bool` | True se la DEPEX è `TRUE`. |
| `DepexExpression::len(&self)` | — | `usize` | Numero di operazioni. |
| `DepexExpression::is_empty(&self)` | — | `bool` | True se vuota. |
| `EfiFvBlockMapEntry::new(num_blocks, block_length)` | `u32`, `u32` | `Self` | Crea una voce della block map. |
| `EfiFvBlockMapEntry::total_bytes(&self)` | — | `u64` | Byte totali coperti da questa voce. |
| `EfiFvBlockMapEntry::is_terminator(&self)` | — | `bool` | True se è la voce terminatore (0,0). |
| `parse_fv_block_map(data)` | `&[u8]` | `Vec<EfiFvBlockMapEntry>` | Parsa la block map di un FV. |
| `PeiModule::new(name, guid)` | `impl Into<String>`, `Guid` | `Self` | Crea un modulo PEI. |
| `PeiModule::dependency_count(&self)` | — | `usize` | Numero di dipendenze. |
| `DxeDriver::new(name, guid)` | `impl Into<String>`, `Guid` | `Self` | Crea un driver DXE. |
| `DxeDriver::protocol_count(&self)` | — | `usize` | Numero di protocolli installati. |
| `DxeDriver::is_smm_driver(&self)` | — | `bool` | True se è un driver SMM. |
| `EfiVariableAttribs::is_non_volatile(self)` | — | `bool` | True se la variabile è non-volatile (NV). |
| `EfiVariableAttribs::is_runtime(self)` | — | `bool` | True se accessibile a runtime (RT). |
| `EfiVariableAttribs::is_authenticated(self)` | — | `bool` | True se autenticata. |
| `EfiVariable::new(name, guid, attrs, data)` | `impl Into<String>`, `Guid`, `u32`, `Vec<u8>` | `Self` | Crea una variabile EFI. |
| `EfiVariable::data_size(&self)` | — | `usize` | Dimensione dati. |
| `EfiVariable::is_secure_boot_related(&self)` | — | `bool` | True per variabili Secure Boot (PK, KEK, db, dbx). |
| `EfiVariableStore::new()` | — | `Self` | Store vuoto. |
| `EfiVariableStore::add(&mut self, v)` | `EfiVariable` | `()` | Aggiunge una variabile. |
| `EfiVariableStore::find_by_name(&self, name)` | `&str` | `Option<&EfiVariable>` | Cerca per nome. |
| `EfiVariableStore::runtime_variables(&self)` | — | `Vec<&EfiVariable>` | Variabili con attributo RT. |
| `EfiVariableStore::secure_boot_variables(&self)` | — | `Vec<&EfiVariable>` | Variabili Secure Boot. |
| `UefiSecurityProfile::build(analysis)` | `&UefiAnalysis` | `Self` | Costruisce il profilo di sicurezza dalla analisi UEFI. |
| `UefiSecurityProfile::is_high_risk(&self)` | — | `bool` | True se lo score di rischio è sopra soglia. |
| `UefiAnalysis::new()` | — | `Self` | Analisi UEFI vuota. |
| `UefiAnalysis::add_fv(&mut self, fv)` | `EfiFirmwareVolume` | `()` | Aggiunge un FV all'analisi. |
| `UefiAnalysis::add_pei_module(&mut self, module)` | `PeiModule` | `()` | Aggiunge un modulo PEI. |
| `UefiAnalysis::add_dxe_driver(&mut self, driver)` | `DxeDriver` | `()` | Aggiunge un driver DXE. |
| `UefiAnalysis::name_for_guid(&self, guid)` | `&Guid` | `Option<&str>` | Risolve un GUID nel database interno. |
| `UefiAnalysis::total_ffs_files(&self)` | — | `usize` | Numero totale di file FFS. |
| `UefiAnalysis::smm_drivers(&self)` | — | `Vec<&DxeDriver>` | Lista driver SMM trovati. |
| `UefiAnalysis::find_pei_module(&self, guid)` | `&Guid` | `Option<&PeiModule>` | Cerca un modulo PEI per GUID. |
| `UefiAnalysis::total_pe_files(&self)` | — | `usize` | Numero totale di PE embedded. |
| `UefiBootServicesProfile::new()` | — | `Self` | Profilo Boot Services vuoto. |
| `UefiBootServicesProfile::risk_level(&self)` | — | `u8` | Livello di rischio 0–100. |
| `UefiBootServicesProfile::is_secure(&self)` | — | `bool` | True se non ci sono chiamate rischiose note. |
| `EfiMemoryDescriptor::new(mem_type, phys, pages)` | `u32`, `u64`, `u64` | `Self` | Crea un descrittore di memoria EFI. |
| `EfiMemoryDescriptor::size_bytes(&self)` | — | `u64` | Dimensione in byte (pages * 4096). |
| `EfiMemoryDescriptor::end_address(&self)` | — | `u64` | Indirizzo fisico di fine. |
| `EfiMemoryDescriptor::is_conventional(&self)` | — | `bool` | True se tipo EfiConventionalMemory. |
| `EfiMemoryDescriptor::is_runtime(&self)` | — | `bool` | True se tipo Runtime. |
| `GptPartitionType::from_u16(v)` | `u16` | `Self` | Converte il tipo di partizione GPT da u16. |
| `GptPartitionEntry::parse_header(data)` | `&[u8]` | `Option<Self>` | Parsa l'header della tabella partizioni GPT. |
| `GptPartitionEntry::is_end(&self)` | — | `bool` | True se è la voce terminatore. |
| `GptHeader::parse(data)` | `&[u8]` | `Option<Self>` | Parsa l'header GPT (magic "EFI PART"). |
| `GptHeader::usable_lba_count(&self)` | — | `u64` | Numero di LBA usabili. |
| `read_cstring(data, offset)` | `&[u8]`, `usize` | `Option<String>` | Legge una C-string null-terminated dall'offset. |
| `align_up(val, align)` | `u64`, `u64` | `u64` | Arrotonda val al multiplo superiore di align. |
| `align_down(val, align)` | `u64`, `u64` | `u64` | Arrotonda val al multiplo inferiore di align. |
| `is_power_of_two(val)` | `u64` | `bool` | True se val è potenza di 2. |
| `byte_entropy(data)` | `&[u8]` | `f64` | Entropia di Shannon in bit per byte. |
| `le_u16(data, off)` | `&[u8]`, `usize` | `u16` | Legge u16 little-endian. |
| `le_u32(data, off)` | `&[u8]`, `usize` | `u32` | Legge u32 little-endian. |
| `le_u64(data, off)` | `&[u8]`, `usize` | `u64` | Legge u64 little-endian. |
| `be_u32(data, off)` | `&[u8]`, `usize` | `u32` | Legge u32 big-endian. |
| `adler32(data)` | `&[u8]` | `u32` | Calcola checksum Adler-32. |
| `find_bytes(haystack, needle)` | `&[u8]`, `&[u8]` | `Option<usize>` | Prima occorrenza di needle in haystack. |
| `count_bytes(haystack, needle)` | `&[u8]`, `&[u8]` | `usize` | Numero di occorrenze di needle. |
| `try_slice(data, offset, len)` | `&[u8]`, `usize`, `usize` | `Option<&[u8]>` | Slice bounds-checked. |
| `is_zeroed(data)` | `&[u8]` | `bool` | True se tutti i byte sono zero. |
| `reverse_bytes(data)` | `&mut [u8]` | `()` | Inverte i byte in-place. |
| `xor_bytes(data, key)` | `&mut [u8]`, `u8` | `()` | XOR in-place con chiave a byte singolo. |
| `rol32(val, n)` | `u32`, `u32` | `u32` | Rotate left 32 bit. |
| `ror32(val, n)` | `u32`, `u32` | `u32` | Rotate right 32 bit. |
| `crc32(data)` | `&[u8]` | `u32` | Calcola CRC-32 (polinomio IEEE 802.3). |
| `fnv1a32(data)` | `&[u8]` | `u32` | Hash FNV-1a 32 bit. |
| `murmur3_32(data, seed)` | `&[u8]`, `u32` | `u32` | Hash MurmurHash3 32 bit. |

---

## Modulo: `signature_db.rs` — Database di segnature

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `SignatureDatabase::new()` | — | `Self` | Crea il database con tutte le segnature built-in (kernel Linux, SquashFS, JFFS2, U-Boot, UEFI, ecc.). |
| `SignatureDatabase::len(&self)` | — | `usize` | Numero di segnature. |
| `SignatureDatabase::is_empty(&self)` | — | `bool` | True se vuoto. |
| `SignatureDatabase::by_category(&self, category)` | `SignatureCategory` | `Vec<&SignatureEntry>` | Filtra segnature per categoria. |
| `SignatureDatabase::by_name(&self, name)` | `&str` | `Option<&SignatureEntry>` | Cerca segnatura per nome. |
| `SignatureDatabase::scan_with_min_confidence<'db>(&'db self, data, min_conf)` | `&[u8]`, `u8` | `Vec<SignatureMatch<'db>>` | Scansiona il buffer restituendo match con confidenza >= min_conf. |
| `SignatureDatabase::scan<'db>(&'db self, data)` | `&[u8]` | `Vec<SignatureMatch<'db>>` | Scansiona restituendo tutti i match. |
| `SignatureDatabase::best_match<'db>(&'db self, data)` | `&[u8]` | `Option<SignatureMatch<'db>>` | Restituisce il match a confidenza massima. |
| `SignatureDatabase::root_matches<'db>(&'db self, data)` | `&[u8]` | `Vec<SignatureMatch<'db>>` | Match trovati all'offset 0 (header). |
| `SignatureDatabase::add_entry(&mut self, entry)` | `SignatureEntry` | `()` | Aggiunge una segnatura custom. |

---

## Modulo: `filesystem_extraction.rs` — Estrazione filesystem

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FilesystemType::as_str(&self)` | — | `&'static str` | Nome del tipo filesystem (squashfs, cramfs, jffs2, ext2, fat). |
| `FsNode::is_file(&self)` | — | `bool` | True se nodo di tipo file. |
| `FsNode::is_dir(&self)` | — | `bool` | True se directory. |
| `FsNode::is_symlink(&self)` | — | `bool` | True se symlink. |
| `ExtractedFilesystem::find(&self, path)` | `&str` | `Option<&FsNode>` | Cerca un nodo per path assoluto. |
| `ExtractedFilesystem::list_dir(&self, dir)` | `&str` | `Vec<&FsNode>` | Lista i figli diretti di una directory. |
| `ExtractedFilesystem::all_files(&self)` | — | `Vec<&str>` | Path di tutti i file. |
| `SquashfsSuperblock::compression_name(&self)` | — | `&'static str` | Nome dell'algoritmo di compressione. |
| `SquashfsSuperblock::detect(data, offset)` | `&[u8]`, `usize` | `Option<SquashfsSuperblock>` | Verifica se il magic SquashFS è presente all'offset. |
| `SquashfsExtractor::extract(data, offset)` | `&[u8]`, `usize` | `ExtractedFilesystem` | Estrae metadati del filesystem SquashFS (stub). |
| `SquashfsScanner::scan(data)` | `&[u8]` | `Vec<usize>` | Trova tutti gli offset con magic SquashFS. |
| `CramfsSuperblock::detect(data, offset)` | `&[u8]`, `usize` | `Option<CramfsSuperblock>` | Rilevamento CramFS per magic. |
| `CramfsExtractor::extract(data, offset)` | `&[u8]`, `usize` | `ExtractedFilesystem` | Estrae metadati CramFS. |
| `Jffs2Scanner::detect(data, offset)` | `&[u8]`, `usize` | `bool` | True se magic JFFS2 presente all'offset. |
| `Jffs2Scanner::scan_nodes(data, base_offset)` | `&[u8]`, `usize` | `Vec<Jffs2Node>` | Lista i nodi JFFS2 trovati. |
| `Jffs2Extractor::extract(data, offset)` | `&[u8]`, `usize` | `ExtractedFilesystem` | Estrae metadati JFFS2. |
| `Ext2Superblock::detect(data, offset)` | `&[u8]`, `usize` | `Option<Ext2Superblock>` | Rilevamento ext2/3/4 per magic 0xEF53. |
| `Ext2Extractor::extract(data, offset)` | `&[u8]`, `usize` | `ExtractedFilesystem` | Estrae metadati ext2. |
| `FatBootSector::detect(data, offset)` | `&[u8]`, `usize` | `Option<FatBootSector>` | Rilevamento FAT per boot sector signature. |
| `FatExtractor::extract(data, offset)` | `&[u8]`, `usize` | `ExtractedFilesystem` | Estrae metadati FAT. |
| `FilesystemExtractor::new()` | — | `Self` | Crea l'estrattore multi-filesystem. |
| `FilesystemExtractor::extract(&mut self, data)` | `&[u8]` | `()` | Esegue la scansione completa di tutti i filesystem supportati. |
| `FilesystemExtractor::summary(&self)` | — | `String` | Riepilogo testuale delle estrazioni. |
| `FilesystemExtractor::successful(&self)` | — | `Vec<&ExtractedFilesystem>` | Filesystem estratti con successo. |
| `FilesystemExtractor::by_type(&self, fs_type)` | `&FilesystemType` | `Vec<&ExtractedFilesystem>` | Filesystem filtrati per tipo. |

---

## Modulo: `firmware_analysis_report.rs` — Report di analisi

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `OsFingerprint::detect(data)` | `&[u8]` | `Self` | Rileva OS embedded (Linux, VxWorks, RTOS, bare-metal). |
| `OsFingerprint::is_linux_based(&self)` | — | `bool` | True se rilevato Linux. |
| `OsFingerprint::is_rtos(&self)` | — | `bool` | True se rilevato RTOS. |
| `CompressionInfo::detect(data)` | `&[u8]` | `Option<Self>` | Rileva tipo di compressione nell'immagine. |
| `FsNode::is_config_file(&self)` | — | `bool` | True se path suggerisce file di configurazione. |
| `FsNode::is_world_writable(&self)` | — | `bool` | True se permessi world-writable. |
| `FsNode::is_setuid(&self)` | — | `bool` | True se bit SUID impostato. |
| `FsTree::find_prefix(&self, prefix)` | `&str` | `Vec<&FsNode>` | Nodi con path che inizia per prefix. |
| `FsTree::setuid_files(&self)` | — | `Vec<&FsNode>` | Lista file setuid. |
| `FsTree::world_writable(&self)` | — | `Vec<&FsNode>` | Lista file world-writable. |
| `CryptoKey::is_high_confidence(&self)` | — | `bool` | True se la chiave ha alta probabilità di essere vera. |
| `NetworkEndpoint::is_private_ip(&self)` | — | `bool` | True se IP privato (RFC1918). |
| `NetworkEndpoint::is_unencrypted(&self)` | — | `bool` | True se protocollo non cifrato (HTTP, Telnet). |
| `NetworkEndpoint::scan(data)` | `&[u8]` | `Vec<Self>` | Scansiona il binario per URL/IP/hostname. |
| `VulnerableComponent::is_high_risk(&self)` | — | `bool` | True se la versione ha vulnerabilità note ad alto rischio. |
| `VulnerableComponent::is_critical(&self)` | — | `bool` | True se CVE critico (CVSS >= 9.0). |
| `FirmwareAnalysisReport::mock()` | — | `Self` | Genera un report fittizio per testing. |
| `FirmwareAnalysisReport::compute_risk_score(&self, …)` | vari campi | `f64` | Calcola lo score di rischio complessivo. |
| `FirmwareAnalysisReport::private_keys(&self)` | — | `Vec<&CryptoKey>` | Chiavi private trovate. |
| `FirmwareAnalysisReport::critical_vulnerabilities(&self)` | — | `Vec<&VulnerableComponent>` | Componenti con vulnerabilità critiche. |
| `FirmwareAnalysisReport::summary(&self)` | — | `String` | Riepilogo testuale del report. |

---

## Modulo: `firmware_security.rs` — Scanner di sicurezza

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FirmwareFinding::new(category, description, risk)` | `impl Into<String>`, `impl Into<String>`, `FwRisk` | `Self` | Crea un finding di sicurezza. |
| `FirmwareFinding::with_offset(self, offset)` | `u64` | `Self` | Aggiunge offset al finding (builder). |
| `FirmwareFinding::with_evidence(self, evidence)` | `impl Into<String>` | `Self` | Aggiunge evidenza testuale (builder). |
| `CredentialScanner::new()` | — | `Self` | Scanner per credenziali (password, API key, token). |
| `CredentialScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona il buffer alla ricerca di credenziali. |
| `CredentialScanner::findings(&self)` | — | `&[FirmwareFinding]` | Finding rilevati. |
| `CredentialScanner::has_credentials(&self)` | — | `bool` | True se almeno una credenziale trovata. |
| `CredentialScanner::matches_of_kind(&self, kind)` | `&str` | `Vec<&CredentialMatch>` | Match di un tipo specifico (password, key, ecc.). |
| `CryptoScanner::new()` | — | `Self` | Scanner per algoritmi crittografici deboli. |
| `CryptoScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona per costanti crittografiche e stringhe. |
| `CryptoScanner::findings(&self)` | — | `&[FirmwareFinding]` | Finding rilevati. |
| `CryptoScanner::algorithm_names(&self)` | — | `Vec<&str>` | Nomi algoritmi identificati. |
| `DebugInterfaceScanner::new()` | — | `Self` | Scanner per interfacce di debug (JTAG, UART, SWD). |
| `DebugInterfaceScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona per stringhe di debug. |
| `DebugInterfaceScanner::findings(&self)` | — | `&[FirmwareFinding]` | Finding rilevati. |
| `DebugInterfaceScanner::has_interface(&self, iface)` | `&DebugInterfaceType` | `bool` | True se interfaccia specifica rilevata. |
| `ShellScanner::new()` | — | `Self` | Scanner per shell e backdoor. |
| `ShellScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona per /bin/sh, /bin/bash, prompt, ecc. |
| `ShellScanner::findings(&self)` | — | `&[FirmwareFinding]` | Finding rilevati. |
| `ShellScanner::has_shell_prompt(&self)` | — | `bool` | True se trovato prompt di shell interattivo. |
| `NetworkServiceScanner::new()` | — | `Self` | Scanner per servizi di rete non sicuri. |
| `NetworkServiceScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona per stringhe telnetd, httpd, ftpd, ecc. |
| `NetworkServiceScanner::findings(&self)` | — | `&[FirmwareFinding]` | Finding rilevati. |
| `NetworkServiceScanner::has_telnetd(&self)` | — | `bool` | True se telnetd rilevato. |
| `FirmwareSecurity::new()` | — | `Self` | Analizzatore di sicurezza aggregato. |
| `FirmwareSecurity::analyse(&mut self, data)` | `&[u8]` | `()` | Esegue tutti gli scanner. |
| `FirmwareSecurity::all_findings(&self)` | — | `Vec<&FirmwareFinding>` | Tutti i finding da tutti gli scanner. |
| `FirmwareSecurity::max_risk(&self)` | — | `Option<FwRisk>` | Rischio massimo trovato. |
| `FirmwareSecurity::has_risk(&self, risk)` | `FwRisk` | `bool` | True se almeno un finding con quel livello di rischio. |
| `FirmwareSecurity::finding_count(&self)` | — | `usize` | Numero totale finding. |
| `FirmwareStringExtractor::new()` | — | `Self` | Estrattore di stringhe configurabile. |
| `FirmwareStringExtractor::with_min_length(self, len)` | `usize` | `Self` | Imposta lunghezza minima (builder). |
| `FirmwareStringExtractor::extract(&self, data)` | `&[u8]` | `Vec<FirmwareString>` | Estrae le stringhe. |
| `FirmwareStringExtractor::find_containing(&self, data, substr)` | `&[u8]`, `&str` | `Vec<FirmwareString>` | Stringhe che contengono una sottostringa. |
| `SecurityScore::score(security)` | `&FirmwareSecurity` | `f64` | Score 0.0–100.0 (100 = sicuro). |
| `SecurityScore::label(score)` | `f64` | `&'static str` | Etichetta testuale (Secure, Low Risk, Medium Risk, High Risk, Critical). |
| `ServiceScanner::new()` | — | `Self` | Scanner servizi generici. |
| `ServiceScanner::scan(&mut self, data)` | `&[u8]` | `()` | Scansiona per nomi di servizi noti. |
| `ServiceScanner::service_names(&self)` | — | `Vec<&str>` | Nomi servizi rilevati. |

---

## Modulo: `extractor.rs` — Estrattore unificato

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `FirmwareExtractor::new()` | — | `Self` | Crea estrattore con configurazione di default. |
| `FirmwareExtractor::with_config(config)` | `ExtractorConfig` | `Self` | Crea estrattore con configurazione custom. |
| `FirmwareExtractor::extract(&self, data)` | `&[u8]` | `Vec<ExtractionResult>` | Scansione completa: segnature + filesystem + entropia. |
| `FirmwareExtractor::extract_at(&self, data, …)` | `&[u8]`, offset, tipo | `Vec<ExtractionResult>` | Estrazione a un offset specifico. |
| `FirmwareExtractor::detect_entropy_regions(&self, data)` | `&[u8]` | `Vec<ExtractionResult>` | Solo analisi entropia: regioni compresse/cifrate. |
| `FirmwareExtractor::full_extract(&self, data)` | `&[u8]` | `Vec<ExtractionResult>` | Pipeline completa con analisi di sicurezza integrata. |
| `FirmwareExtractor::summarize(results)` | `&[ExtractionResult]` | `ExtractionSummary` | Aggrega i risultati in un riepilogo. |

---

## Conteggio funzioni pubbliche

Totale funzioni `pub fn` (incluse `pub async fn` e metodi `pub fn` su `impl`): **~270**
