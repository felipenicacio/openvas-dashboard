from app.routers.vulnerabilities import _serialize_vulnerability


def test_serialize_vulnerability_splits_cves():
    row = {
        "id": "1",
        "cves": "CVE-2024-0001,CVE-2024-0002",
    }

    item = _serialize_vulnerability(row)

    assert item["cves"] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_serialize_vulnerability_empty_cves_becomes_list():
    row = {
        "id": "1",
        "cves": "",
    }

    item = _serialize_vulnerability(row)

    assert item["cves"] == []


def test_serialize_vulnerability_ignores_blank_entries():
    row = {
        "id": "1",
        "cves": " CVE-2024-0001, ,CVE-2024-0002 ",
    }

    item = _serialize_vulnerability(row)

    assert item["cves"] == ["CVE-2024-0001", "CVE-2024-0002"]
