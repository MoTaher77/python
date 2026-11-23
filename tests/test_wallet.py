import os
import tempfile

os.environ["WALLET_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")

from fastapi.testclient import TestClient  # noqa: E402

from wallet.main import app  # noqa: E402


def mk(c, name, phone):
    assert c.post("/api/register", json={"name": name, "phone": phone, "pin": "1234"}).status_code == 201
    t = c.post("/api/login", json={"phone": phone, "pin": "1234"}).json()["token"]
    return {"Authorization": f"Bearer {t}"}


def test_flow():
    with TestClient(app) as c:
        a = mk(c, "أحمد", "771000001")
        b = mk(c, "سالم", "771000002")
        assert c.post("/api/deposit", json={"amount": 1000}, headers=a).json()["balance"] == 1000
        assert c.post("/api/transfer", json={"to_phone": "771000002", "amount": 250.5, "pin": "1234"}, headers=a).status_code == 200
        assert c.get("/api/me", headers=a).json()["balance"] == 749.5
        assert c.get("/api/me", headers=b).json()["balance"] == 250.5
        assert c.post("/api/withdraw", json={"amount": 5000, "pin": "1234"}, headers=a).status_code == 400
        assert c.post("/api/withdraw", json={"amount": 10, "pin": "0000"}, headers=a).status_code == 403
        assert c.post("/api/bills", json={"provider": "water", "reference": "A123", "amount": 50, "pin": "1234"}, headers=a).status_code == 200
        assert c.post("/api/topup", json={"provider": "sabafon", "phone": "733000000", "amount": 20, "pin": "1234"}, headers=a).status_code == 200
        assert len(c.get("/api/transactions", headers=a).json()) == 4
        assert c.post("/api/transfer", json={"to_phone": "771000001", "amount": 1, "pin": "1234"}, headers=a).status_code == 400
        assert c.post("/api/deposit", json={"amount": -5}, headers=a).status_code == 400
        assert c.get("/api/me").status_code == 401
