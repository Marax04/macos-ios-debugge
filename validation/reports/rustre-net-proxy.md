# rustre-net-proxy

Crate per proxy di rete con supporto SOCKS5, HTTP CONNECT, TLS MITM, intercettazione WebSocket, logging del traffico e analisi di sicurezza passiva.

**Versione**: workspace  
**Dipendenze chiave**: `rustre-net`, `tokio`, `rustls`, `rcgen`, `tokio-rustls`, `serde_json`

---

## Moduli

| Modulo | Responsabilità |
|--------|----------------|
| `lib.rs` | Core: SOCKS5/HTTP proxy, MITM, session manager, rate limiter, DNS cache, intruder engine, scanner passivo, esportatori (HAR, PCAP, Burp), JA3/JA4 fingerprinting |
| `mitm_engine.rs` | Engine MITM con catena di interceptor, queue request/response, session tracker, statistiche |
| `tls_proxy.rs` | Parsing TLS record/ClientHello, generazione certificati on-the-fly, gestione sessioni TLS |
| `traffic_logger.rs` | Logger ad anello con filtri, esportazione PCAP/HAR, replay batch |
| `http_interceptor.rs` | Parsing HTTP (versione, metodo, header map), intercettazione rule-based, harvesting credenziali, rilevamento SSL stripping |
| `websocket.rs` | Parsing/serializzazione frame WebSocket, riassemblaggio messaggi frammentati |
| `upstream.rs` | Pool connessioni per host, proxy upstream con autenticazione, chain di proxy |

---

## Funzioni pubbliche libere (free fn) — 21

| Funzione | File | Input | Output | Descrizione |
|----------|------|-------|--------|-------------|
| `detect_websocket_upgrade(req)` | websocket.rs | `&HttpRequest` | `bool` | Verifica se la richiesta contiene header `Upgrade: websocket` |
| `parse_websocket_stream(data)` | websocket.rs | `&[u8]` | `Vec<WebSocketFrame>` | Decodifica uno stream raw TCP in frame WebSocket; gestisce masking client-side |
| `reassemble_ws_messages(frames)` | websocket.rs | `&[WebSocketFrame]` | `Vec<WebSocketFrame>` | Riassembla frame frammentati (FIN=0) in messaggi completi |
| `generate_cert_for_host(hostname)` | tls_proxy.rs | `&str` | `Result<GeneratedCert, ProxyError>` | Genera coppia cert/key TLS firmata dalla CA interna per il dominio indicato (via `rcgen`) |
| `extract_sni_from_tcp_payload(data)` | tls_proxy.rs | `&[u8]` | `Option<String>` | Estrae l'SNI da un payload TCP grezzo che inizia con un ClientHello TLS |
| `inject_xff_headers(data, client_ip, proxy_host)` | lib.rs | `&mut Vec<u8>`, `&str`, `&str` | `bool` | Inietta `X-Forwarded-For` e `Via` in un buffer HTTP già serializzato; ritorna `true` se modificato |
| `apply_rules_to_request(rules, req)` | lib.rs | `&[MatchReplaceRule]`, `&mut HttpRequest` | `usize` | Applica le regole match-replace alla richiesta; ritorna il numero di regole scattate |
| `apply_rules_to_response(rules, resp)` | lib.rs | `&[MatchReplaceRule]`, `&mut HttpResponse` | `usize` | Come sopra, ma sulla risposta |
| `hex_decode(hex)` | lib.rs | `&str` | `Option<Vec<u8>>` | Decodifica una stringa esadecimale in bytes |
| `hex_encode(bytes)` | lib.rs | `&[u8]` | `String` | Codifica bytes in stringa esadecimale lowercase |
| `glob_match(pattern, text)` | lib.rs | `&str`, `&str` | `bool` | Pattern matching con wildcard `*` e `?` per regole di scope/ACL |
| `simple_regex_match(pattern, text)` | lib.rs | `&str`, `&str` | `bool` | Regex semplificato (`.`, `*`, `^`, `$`, classi) senza dipendenze esterne |
| `simple_regex_match_len(pattern, text)` | lib.rs | `&str`, `&str` | `usize` | Come sopra, ritorna la lunghezza del match invece di bool |
| `base64_decode(encoded)` | lib.rs | `&str` | `Option<Vec<u8>>` | Decodifica Base64 standard (usato per parsing `Authorization: Basic`) |
| `decode_content_encoding(data, encoding)` | lib.rs | `&[u8]`, `&str` | `Vec<u8>` | Decodifica body HTTP compresso (`gzip`, `deflate`, `identity`) |
| `decode_http_response_body(resp)` | lib.rs | `&HttpResponse` | `(Vec<u8>, String)` | Decomprime il body della risposta e ritorna `(bytes, encoding_usato)` |
| `extract_jwt_tokens(entries)` | lib.rs | `&[RequestLogEntry]` | `Vec<JwtToken>` | Scansiona l'history di richieste e restituisce tutti i JWT trovati (header/body) |
| `handle_connect_tunnel(…)` | lib.rs | stream, upstream addr, hook, stats | `Result<(), ProxyError>` (async) | Gestisce un tunnel CONNECT bidirezionale con bidirectional copy e hook di intercettazione |
| `detect_ssl_strip(request_url, response)` | http_interceptor.rs | `&str`, `&HttpResponse` | `SslStripAnalysis` | Rileva tentativi di SSL stripping confrontando URL e redirect della risposta |
| `harvest_credentials(req)` | http_interceptor.rs | `&HttpRequest` | `Vec<HarvestedCredential>` | Estrae credenziali da form POST, Basic Auth, Bearer token, query string |
| `rewrite_body(body, find, replace)` | http_interceptor.rs | `&[u8]`, `&[u8]`, `&[u8]` | `Vec<u8>` | Cerca e sostituisce una sequenza di byte nel body HTTP |

---

## Metodi pubblici per tipo — 384 totali (sintesi per tipo)

### `WebSocketFrame` (websocket.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `parse(data)` | `&[u8]` | `Option<(Self, usize)>` | Decodifica un frame dal buffer; ritorna frame + byte consumati |
| `serialize()` | `&self` | `Vec<u8>` | Serializza il frame in bytes con masking se richiesto |
| `payload_str()` | `&self` | `Cow<str>` | Vista UTF-8 del payload (lossy) |
| `text(payload)` | `impl Into<String>` | `Self` | Costruttore frame TEXT |
| `close(code, reason)` | `u16`, `&str` | `Self` | Costruttore frame CLOSE con codice RFC 6455 |

### `ConnectionPool` (upstream.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(max_per_host)` | `usize` | `Self` | Pool con limite di connessioni per host |
| `acquire(host)` | `&str` | `bool` | Tenta di acquisire uno slot; `false` se il limite è raggiunto |
| `release(host)` | `&str` | `()` | Rilascia uno slot precedentemente acquisito |
| `active_for(host)` | `&str` | `usize` | Connessioni attive per il dato host |
| `total_active()` | — | `usize` | Totale connessioni attive in tutti gli host |

### `UpstreamProxy` (upstream.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(host, port, proto)` | `&str`, `u16`, `ProxyProtocol` | `Self` | Configura un proxy upstream (HTTP/SOCKS5) |
| `with_auth(username, password)` | `&str`, `&str` | `Self` | Aggiunge credenziali di autenticazione (builder) |
| `addr_str()` | `&self` | `String` | Ritorna `"host:port"` |

### `UpstreamChain` (upstream.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new()` | — | `Self` | Catena vuota di proxy upstream |
| `push(proxy)` | `UpstreamProxy` | `()` | Aggiunge un proxy in fondo alla catena |
| `first()` | `&self` | `Option<&UpstreamProxy>` | Ritorna il primo proxy della catena |

### `TrafficLogger` (traffic_logger.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(max_entries)` | `usize` | `Self` | Ring buffer di log con capacità massima |
| `push(entry)` | `LogEntry` | `()` | Aggiunge un entry; se pieno, sovrascrive il più vecchio |
| `all()` | `&self` | `Vec<LogEntry>` | Restituisce tutti gli entry correnti |
| `filter(rule)` | `&FilterRule` | `Vec<LogEntry>` | Filtra per host, status, tag, metodo, ecc. |
| `get(id)` | `u64` | `Option<LogEntry>` | Recupera entry per ID |
| `export_pcap()` | `&self` | `Vec<u8>` | Esporta il traffico in formato PCAP (magic + record header per entry) |
| `export_har(filter)` | `Option<&FilterRule>` | `String` | Esporta in formato HAR JSON |
| `total_bytes()` | `&self` | `u64` | Somma bytes request+response di tutti gli entry |
| `error_count()` | `&self` | `usize` | Conta gli entry con status 4xx/5xx o errore connessione |

### `TlsHandshakeParser` (tls_proxy.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `parse_client_hello(data)` | `&[u8]` | `Result<ClientHello, ProxyError>` | Analizza un record TLS e ne estrae il ClientHello |
| `extract_sni(data)` | `&[u8]` | `Option<String>` | Estrai solo l'SNI senza parsing completo |

### `TlsProxy` (tls_proxy.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(mitm_certs)` | `bool` | `Self` | Crea il proxy TLS; se `mitm_certs=true` genera certificati on-the-fly |
| `new_session(client_addr)` | `SocketAddr` | `u64` | Apre una nuova sessione TLS, ritorna un ID sessione |
| `feed(id, data)` | `u64`, `&[u8]` | `Result<(), ProxyError>` | Alimenta dati raw alla sessione TLS identificata da `id` |
| `get_or_generate_cert(hostname)` | `&str` | `Result<(String, String), ProxyError>` | Ritorna (cert_pem, key_pem) per il dominio, generandolo se non in cache |
| `close_session(id)` / `remove_session(id)` | `u64` | `()` | Chiude/rimuove la sessione dal tracker |
| `session_count()` / `cert_cache_size()` | — | `usize` | Metriche runtime |

### `MitmEngine` (mitm_engine.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(config)` | `MitmConfig` | `Result<Self, MitmError>` | Crea l'engine MITM con configurazione esplicita |
| `with_defaults()` | — | `Result<Self, MitmError>` | Crea l'engine con configurazione di default |
| `start()` / `stop()` | `&self` | `Result<(), MitmError>` | Avvia/ferma l'engine |
| `add_interceptor(interceptor)` | `impl Interceptor` | `()` | Aggiunge un interceptor alla catena |
| `open_session(client, target)` | `SocketAddr`, `SocketAddr` | `Result<u64, MitmError>` | Registra una nuova sessione MITM, ritorna ID |
| `handle_request(session_id, req)` | `u64`, `HttpRequest` | `Result<InterceptAction, MitmError>` | Passa la richiesta attraverso la catena interceptor |
| `handle_response(session_id, resp)` | `u64`, `HttpResponse` | `Result<InterceptAction, MitmError>` | Passa la risposta attraverso la catena interceptor |
| `stats()` | `&self` | `MitmStats` | Snapshot delle statistiche (richieste, risposte, dropped) |
| `report()` | `&self` | `MitmReport` | Report completo con statistiche e top sessioni |

### `CertificateAuthority` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new()` | — | `Result<Self, MitmError>` | Genera una nuova CA root in memoria (ECDSA P-256) |
| `sign_for_host(hostname)` | `&str` | `Result<(String, String), MitmError>` | Firma un certificato leaf per il dominio dato |
| `load_or_create(path)` | `&Path` | `Result<Self, MitmError>` | Carica la CA da file PEM oppure ne crea una nuova |
| `ca_cert_pem()` / `ca_cert_der_bytes()` | `&self` | `&str` / `Vec<u8>` | Restituisce il certificato CA in formato PEM o DER |
| `build_server_config(hostname)` | `&str` | `Result<Arc<ServerConfig>, MitmError>` | Costruisce la `ServerConfig` rustls per intercettare una connessione TLS |
| `build_client_config()` | — | `Result<Arc<ClientConfig>, MitmError>` | Costruisce la `ClientConfig` rustls per connettersi all'upstream accettando qualsiasi CA |

### `MitmProxy` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(bind_addr)` | `SocketAddr` | `Result<Self, MitmError>` | Crea un proxy MITM che si lega sull'indirizzo indicato |
| `with_ca_path(bind_addr, path)` | `SocketAddr`, `&Path` | `Result<Self, MitmError>` | Come `new` ma carica/crea la CA da file |
| `with_logger(logger)` | `Arc<RequestLogger>` | `Self` | Collega un logger alle richieste (builder) |
| `add_rule(rule)` | `MatchReplaceRule` | `()` | Aggiunge una regola match-replace attiva |
| `start_https(bind_addr)` | `SocketAddr` | `Result<(), MitmError>` (async) | Avvia il listener HTTPS MITM |
| `handle_connect_from_accepted(stream)` | `TcpStream` | `Result<(), MitmError>` (async) | Gestisce una connessione CONNECT già accettata |
| `stats()` | `&self` | `ProxyStats` | Snapshot corrente di byte/connessioni/errori |

### `ProxyServer` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(config, hook)` | `ProxyConfig`, `Arc<dyn InterceptHook>` | `Self` | Crea il server proxy con hook personalizzato |
| `passthrough(config)` | `ProxyConfig` | `Self` | Crea il server in modalità passthrough (hook no-op) |
| `run(self)` | `Arc<Self>` | `Result<(), ProxyError>` (async) | Avvia il loop accettazione connessioni Tokio |
| `stats()` | `&self` | `ProxyStats` | Statistiche aggregate |
| `get_ca_cert()` | — | `Result<Vec<u8>, ProxyError>` | Restituisce il DER della CA interna |
| `generate_ca()` | — | `Result<(Vec<u8>, Vec<u8>), ProxyError>` | Genera una nuova CA e ritorna `(cert_der, key_der)` |

### `Socks5Proxy` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `handshake(stream, config)` | `&mut TcpStream`, `&ProxyConfig` | `Result<SocketAddr, ProxyError>` (async) | Esegue l'handshake SOCKS5 (metodo auth + richiesta CONNECT), ritorna l'indirizzo target |

### `HttpProxy` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `parse_connect(request)` | `&str` | `Option<String>` | Estrae l'host dalla riga `CONNECT host:port HTTP/1.1` |
| `handshake(stream)` | `&mut TcpStream` | `Result<String, ProxyError>` (async) | Legge la richiesta HTTP CONNECT e ritorna `"host:port"` |
| `send_connect_ok(stream)` | `&mut TcpStream` | `Result<(), ProxyError>` (async) | Invia `200 Connection established` |
| `send_connect_err(stream)` | `&mut TcpStream` | `Result<(), ProxyError>` (async) | Invia `502 Bad Gateway` |

### `ProxyAcl` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `add(entry)` | `AclEntry` | `()` | Aggiunge una regola ACL |
| `evaluate(host, port)` | `&str`, `u16` | `AclAction` | Valuta la lista in ordine; ritorna `Allow` o `Deny` |

### `RequestLogger` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new(max_entries)` | `usize` | `Self` | Ring buffer di entry request/response |
| `log(req, resp, timestamp)` | `&HttpRequest`, `&HttpResponse`, `u64` | `()` | Aggiunge un entry al log |
| `history()` | `&self` | `Vec<RequestLogEntry>` | Tutti gli entry correnti |
| `by_method(method)` | `&str` | `Vec<RequestLogEntry>` | Filtra per metodo HTTP |
| `by_url_contains(substr)` | `&str` | `Vec<RequestLogEntry>` | Filtra per sottostringa dell'URL |
| `export_har()` | `&self` | `String` | Esporta in formato HAR JSON |

### `TrafficAnalyzer` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `analyze_beacons(entries)` | `&[RequestLogEntry]` | `Vec<BeaconGroup>` | Raggruppa richieste periodiche che suggeriscono C2 beaconing |
| `detect_exfil(entries)` | `&[RequestLogEntry]` | `Vec<ExfilEvent>` | Individua trasferimenti dati anomali (large POST, DNS tunneling) |
| `find_credentials(entries)` | `&[RequestLogEntry]` | `Vec<FoundCredential>` | Scansiona header e body per token, password in chiaro, chiavi API |
| `c2_indicators(entries)` | `&[RequestLogEntry]` | `Vec<C2Indicator>` | Euristiche C2: User-Agent rari, JA3 noti, domini DGA |

### `Ja3Fingerprinter` / `Ja4Fingerprinter` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `compute(hello)` | `&ClientHelloFields` | `String` | Calcola l'hash JA3 (MD5 dei cipher/extension/curve concatenati) |
| `compute_ja4(hello)` | `&ClientHelloFields` | `String` | Calcola il fingerprint JA4 (formato `tXXXXXX_YYYY_ZZZZ`) |

### `PassiveVulnScanner` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `scan(entries)` | `&[RequestLogEntry]` | `Vec<SecurityFinding>` | Rileva passivamente: cookie senza Secure/HttpOnly, HSTS mancante, header esposti, CORS permissivi, ecc. |

### `IntruderEngine` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `generate_candidates(template)` | `&IntruderTemplate` | `Vec<IntruderCandidate>` | Genera tutte le varianti di payload per le posizioni marcate |
| `attack_sniper(template, payloads)` | `&IntruderTemplate`, `&[Vec<u8>]` | `Vec<IntruderCandidate>` | Attacco Sniper: un payload alla volta per ogni posizione |
| `attack_battering_ram(template, payloads)` | `&IntruderTemplate`, `&[Vec<u8>]` | `Vec<IntruderCandidate>` | Stesso payload iniettato in tutte le posizioni contemporaneamente |

### `HarExporter` / `PcapExporter` / `BurpExporter` / `MitmproxyExporter` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `export(entries)` | `&[RequestLogEntry]` | `String` / `Vec<u8>` | Esporta il traffico nel formato specifico (HAR JSON, PCAP binario, XML Burp Suite, file mitmproxy) |

### `SessionManager` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new_session(client_addr, target_addr, proto)` | `&str`, `&str`, `ProxyProtocol` | `u64` | Registra una nuova sessione, ritorna ID incrementale |
| `set_state(id, state)` | `u64`, `SessionState` | `()` | Aggiorna lo stato della sessione (Active, Closed, Error) |
| `add_bytes(id, bytes_in, bytes_out)` | `u64`, `u64`, `u64` | `()` | Aggiorna i contatori di traffico della sessione |
| `active()` | `&self` | `Vec<SessionEntry>` | Lista delle sessioni attive |
| `prune()` | `&self` | `()` | Rimuove le sessioni chiuse/in errore dal tracker |

### `RateLimiter` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `try_connect()` | `&self` | `bool` | Tenta di aprire una connessione rispettando il limite configurato |
| `release_connection()` | `&self` | `()` | Rilascia un token connessione |
| `try_send_bytes(now_ms, bytes)` | `u64`, `u64` | `bool` | Controlla il bandwidth limit (token bucket) |

### `DnsCache` (lib.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `insert(host, ip, ttl_secs, now_ms)` | `&str`, `String`, `u64`, `u64` | `()` | Inserisce una entry con TTL |
| `lookup(host, now_ms)` | `&str`, `u64` | `Option<String>` | Cerca un'entry non scaduta |
| `evict_expired(now_ms)` | `u64` | `usize` | Rimuove le entry scadute; ritorna il numero rimosso |

### `HttpInterceptor` (http_interceptor.rs)
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `add_rule(rule)` | `InterceptRule` | `()` | Aggiunge una regola di intercettazione |
| `intercept_request(req)` | `&mut HttpRequest` | `Option<HttpResponse>` | Applica le regole alla richiesta; `Some(resp)` se va bloccata/sostituita |
| `intercept_response(resp)` | `&mut HttpResponse` | `()` | Applica le regole alla risposta |

---

## Trait pubblici

| Trait | Metodi richiesti | Descrizione |
|-------|-----------------|-------------|
| `InterceptHook` | `on_request(&ProxyRequest) -> HookAction`, `on_response(&ProxyResponse)` | Hook di intercettazione per `ProxyServer` |
| `Interceptor` (mitm_engine) | `name()`, `intercept_request(…)`, `intercept_response(…)` | Singolo interceptor per `InterceptorChain` |
| `ProxyPlugin` | `on_request(…)`, `on_response(…)` | Plugin per `SpecProxyConfig` |
| `DataModifier` | `apply(data: &mut Vec<u8>) -> bool` | Trasformatore di payload per `ModifierPipeline` |

---

## Enum pubblici principali

| Enum | Varianti | Utilizzo |
|------|---------|---------|
| `ProxyMode` | `Http`, `Socks5`, `Transparent`, `Reverse` | Modalità operativa del proxy |
| `HookAction` | `Passthrough`, `Block`, `Replace(ProxyResponse)` | Azione restituita da `InterceptHook::on_request` |
| `InterceptAction` | `Forward`, `Drop`, `Modify`, `Respond(HttpResponse)` | Azione dal chain MITM |
| `AclAction` | `Allow`, `Deny` | Risultato valutazione ACL |
| `TlsContentType` | `ChangeCipherSpec`, `Alert`, `Handshake`, `ApplicationData` | Tipo record TLS |
| `WsOpcode` | `Continuation`, `Text`, `Binary`, `Close`, `Ping`, `Pong` | Opcode frame WebSocket |
| `FindingSeverity` | `Info`, `Low`, `Medium`, `High`, `Critical` | Severità finding scanner passivo |
| `AttackType` | `Sniper`, `BatteringRam`, `Pitchfork`, `ClusterBomb` | Modalità attacco Intruder |
| `ProxyProtocol` | `Http`, `Https`, `Socks5` | Protocollo per `SessionManager` e `UpstreamProxy` |

---

## Statistiche

- **Funzioni pubbliche totali**: 405 (21 libere + 384 metodi)
- **Tipi pubblici**: ~70 (struct + enum + trait)
- **File sorgente**: 6 moduli + lib.rs
