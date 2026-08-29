# Sprint 0-5 architecture

```text
PCAP -> Zeek (when installed)
        |
        v
Zeek conn.log JSONL
        |
        v
ZeekConnectionReader
        |
        v
NetworkEvent (shared contract)
        |
        v
Shared sliding-window engine
        |
        +--> ReconDetector (per source)
        |
        +--> DDoSDetector (per target)
        |
        v
Alert + Evidence[]
        |
        v
JSONL alerts + replay-health JSON
```

```text
Zeek dns.log JSONL
        |
        v
DNSEvent (DNS-specific versioned contract)
        |
        +--> Registered-domain character 3-gram model --> DGA-like alert
        |
        +--> Per-client/base-domain sliding window
                    |
                    +--> volume + diversity + length + entropy --> tunnelling alert
        |
        v
Shared Alert + Evidence[] contract
```

The DGA model and tunnelling detector remain separate because one scores domain-name
patterns while the other scores repeated behaviour over time. Neither path sends
traffic toward the monitored network.

```text
Zeek conn.log --------------------> Per-endpoint connection window
                                             |
                                   interval + jitter + size CV
                                             |
Zeek ssl.log / quic.log --> metadata context + anomaly score
                                             |
                                             v
                                Periodic C2 beacon alert
```

Encrypted metadata can enrich confidence and evidence but cannot trigger an alert
without repeated timing and size behaviour.

```text
NetworkEvent --> outbound byte window + source baseline --> Exfiltration Alert
                                                             |
Recon / DDoS / DNS / C2 alerts -------------------------------+
                                                             v
                                  IncidentStore by source and time
                                                             |
                              deterministic score + deduplication
                                                             |
                                                             v
                              Incident + standard Alert records
                                                             |
                     automatic repository upsert when database configured
                                                             |
                                          SQLite or PostgreSQL
```

Incident confidence, deterministic risk score, and policy severity are stored as
separate values. Approved backups are suppressed before exfiltration alert creation.

```text
Incident + Alert JSONL --> automatic persistent repository --> FastAPI analyst service
                                |                         |
                         SQLite local demo          versioned REST API
                         PostgreSQL Docker                |
                                                          v
                                           React/TypeScript console
                                           queue -> evidence -> review
                                                          |
                                        status + feedback + JSON export
```

The analyst system stays on the monitoring side of the one-way boundary. It never
opens a connection toward the protected network. SQLite supports the fast local demo;
the Docker topology uses the equivalent PostgreSQL schema for durable team use.
The correlation command performs an idempotent upsert when `--database` or
`AEGISFLOW_DB` is present. Reprocessing detector output updates evidence while retaining
the analyst-owned incident status.

## Boundary assumptions

- Input is a copied or replayed observation on the monitoring side.
- The pipeline has no network-response or packet-injection function.
- Payload content is not required by the shared event contract.
- Raw-packet retention is outside the current implementation.
- `conn.log` cannot provide packet-capture loss by itself; the health report marks that visibility as unavailable rather than reporting zero loss.

## Extension contract

Future detectors implement `Detector.process(event) -> list[Alert]`. Protocol adapters normalize input into the shared contract or a versioned extension. Correlation will consume standard alerts without detector-specific code.
