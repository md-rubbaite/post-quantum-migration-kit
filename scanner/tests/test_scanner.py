import json
from datetime import date
from pathlib import Path

import pytest

from pqcscan.cli import main
from pqcscan.report import to_sarif
from pqcscan.rules import RULES
from pqcscan.scanner import Settings, priority, scan_path, scan_text, summarise

EXAMPLES = Path(__file__).parents[2] / "examples"
APP = EXAMPLES / "legacy-app"


def settings(**kw):
    return Settings(today=date(2026, 11, 22), **kw)


def rules_in(text, kind, **kw):
    return sorted({f.rule for f in scan_text(text, "x", kind, settings(**kw))})


@pytest.mark.parametrize(
    "text,kind,expected",
    [
        ("var k = RSA.Create(3072);", "cs", "PQC001"),
        ("sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);", "cs", "PQC002"),
        ('KeyPairGenerator.getInstance("RSA")', "java", "PQC003"),
        ("rsa.generate_private_key(public_exponent=65537, key_size=2048)", "py", "PQC004"),
        ("crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })", "js", "PQC005"),
        ("k, _ := rsa.GenerateKey(rand.Reader, 2048)", "go", "PQC006"),
        ("using var dh = ECDiffieHellman.Create();", "cs", "PQC010"),
        ("priv, _ := ecdh.X25519().GenerateKey(rand.Reader)", "go", "PQC011"),
        ("const dh = crypto.createDiffieHellman(2048);", "js", "PQC012"),
        ("using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);", "cs", "PQC020"),
        ("key = ec.generate_private_key(ec.SECP256R1())", "py", "PQC020"),
        ("key = Ed25519PrivateKey.generate()", "py", "PQC021"),
        ('"alg": "ES256"', "config", "PQC030"),
        ("SecurityAlgorithms.RsaSha256", "cs", "PQC030"),
        ("ssh-ed25519 AAAAC3Nza demo", "key", "PQC032"),
        ("ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;", "config", "PQC033"),
        ("ssl_protocols TLSv1 TLSv1.2;", "config", "PQC034"),
        ("h = hashlib.md5(b)", "py", "PQC040"),
        ("var h = SHA1.HashData(b);", "cs", "PQC041"),
        ("var d = TripleDES.Create();", "cs", "PQC042"),
        ("using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);", "cs", "PQC090"),
        ("using var k = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);", "cs", "PQC091"),
    ],
)
def test_rule_detects(text, kind, expected):
    assert expected in rules_in(text, kind)


@pytest.mark.parametrize(
    "text,kind",
    [
        ("var h = SHA256.HashData(b);", "cs"),
        ("using var aes = Aes.Create(); aes.KeySize = 256;", "cs"),
        ("ssl_protocols TLSv1.2 TLSv1.3;", "config"),
        ("ssl_ecdh_curve X25519MLKEM768;", "config"),
        ("// RSA is mentioned in a comment about history", "py"),
    ],
)
def test_safe_code_is_not_flagged_as_vulnerable(text, kind):
    vulnerable = [f for f in scan_text(text, "x", kind, settings()) if f.category != "post-quantum"]
    assert vulnerable == []


def test_language_specific_rules_do_not_fire_on_other_languages():
    assert "PQC001" not in rules_in("RSA.Create()", "py")


def test_inline_suppression():
    assert rules_in("h = hashlib.md5(b)  # pqcscan:ignore", "py") == []


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_harvest_now_decrypt_later_makes_key_establishment_critical():
    # 2026: 9 years until 2035. 10 years of confidentiality + 3 years of migration > 9.
    assert priority("key-establishment", settings(data_shelf_life_years=10, migration_years=3)) == "critical"
    # Short-lived data (1 year) migrated in 2 years stays within the horizon.
    assert priority("key-establishment", settings(data_shelf_life_years=1, migration_years=2)) == "high"


def test_signature_priority_depends_on_time_to_deprecation():
    assert priority("signature", settings(migration_years=3)) == "medium"  # 4 years until end of 2030
    assert priority("signature", settings(migration_years=4)) == "high"


def test_sample_application_inventory():
    findings = scan_path(APP, settings())
    found = {(f.file, f.rule) for f in findings}
    assert ("src/PaymentTokenService.cs", "PQC001") in found
    assert ("src/PaymentTokenService.cs", "PQC020") in found
    assert ("src/report_signer.py", "PQC020") in found
    assert ("src/session.go", "PQC011") in found
    assert ("config/nginx.conf", "PQC033") in found
    assert ("config/appsettings.json", "PQC030") in found
    assert ("keys/deploy.pub", "PQC031") in found
    assert ("src/HybridClient.java", "PQC090") in found
    # The md5 call in report_signer.py is suppressed after review.
    assert not any(f.file == "src/report_signer.py" and f.rule == "PQC040" for f in findings)
    assert findings[0].priority == "critical"
    s = summarise(findings)
    assert s["post_quantum_in_use"] == 1 and s["files_affected"] == 6


def test_exclude_patterns(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.cs").write_text("RSA.Create();")
    (tmp_path / "app.cs").write_text("RSA.Create();")
    files = {f.file for f in scan_path(tmp_path, settings(exclude=["vendor/**"]))}
    assert files == {"app.cs"}


def test_skips_build_output_and_unknown_files(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "x.cs").write_text("RSA.Create();")
    (tmp_path / "notes.txt").write_text("RSA.Create();")
    assert scan_path(tmp_path, settings()) == []


def test_sarif_is_valid_shape():
    doc = json.loads(to_sarif(scan_path(APP, settings())))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}


@pytest.mark.parametrize("fmt", ["text", "json", "sarif", "markdown"])
def test_cli_formats(fmt, tmp_path):
    out = tmp_path / f"report.{fmt}"
    code = main([str(APP), "--config", str(EXAMPLES / "pqcscan.toml"), "--format", fmt, "--out", str(out)])
    assert code == 0 and out.stat().st_size > 100
    if fmt == "json":
        doc = json.loads(out.read_text())
        assert doc["policy"]["quantum_vulnerable_disallowed_after"] == 2035


def test_cli_fail_on_threshold():
    assert main([str(APP), "--fail-on", "critical"]) == 1
    assert main([str(EXAMPLES / "legacy-app" / "src" / "HybridClient.java"), "--fail-on", "medium"]) == 0


def test_cli_rejects_bad_config(tmp_path):
    bad = tmp_path / "c.toml"
    bad.write_text("[pqcscan]\nshelf = 3\n")
    assert main([str(APP), "--config", str(bad)]) == 2
    assert main([str(tmp_path / "missing")]) == 2
