# iocsift

**Ruby** — Extract & defang IOCs (IPs, domains, URLs, emails, hashes) from any text.

[![ci](https://github.com/cognis-digital/iocsift/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/iocsift/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Ruby-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `iocsift` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "io_cpe": {
    "windows_xp_sp2": {
      "cve_ids": ["CVE-2021-34567"],
      "ioc_count": 10,
      "iocs": [
        {"sha256": "1234567890abcdef", "name": "Malware1.exe"},
        {"sha256": "2345678901cdfghij", "name": "Malware2.dll"}
      ]
    }
  }
}
```

<!-- cognis:example:end -->

## Build / run

```bash
ruby iocsift.rb sample.txt   # no build step; pure Ruby
```

## Usage

```
ruby iocsift.rb report.txt
cat alert.eml | ruby iocsift.rb -
  --no-defang   keep indicators live
```

## Output

A JSON object on stdout. Exit code **2** when findings exist, **0** when clean, **1** on error — so you can gate CI/pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
