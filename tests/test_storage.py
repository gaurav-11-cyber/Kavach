import pytest
 
from analyzer import storage
 
 
@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "test.db"))
 
 
def fake(score=10, level="LOW", package="com.x"):
    return {"info": {"package": package}, "risk": {"score": score, "level": level}}
 
 
def test_save_list_and_get_roundtrip():
    new_id = storage.save_result("a.apk", "h1", fake())
    rows = storage.list_results()
    assert len(rows) == 1 and rows[0]["filename"] == "a.apk"
    record = storage.get_result(new_id)
    assert record is not None
    assert record["result"]["info"]["package"] == "com.x"
 
 
def test_same_hash_replaces_old_result():
    storage.save_result("a.apk", "h1", fake(score=10))
    storage.save_result("a.apk", "h1", fake(score=55, level="MEDIUM"))
    rows = storage.list_results()
    assert len(rows) == 1 and rows[0]["score"] == 55
 
 
def test_missing_id_returns_none():
    assert storage.get_result(999) is None
 
 
def test_newest_result_listed_first():
    storage.save_result("a.apk", "h1", fake())
    storage.save_result("b.apk", "h2", fake())
    assert storage.list_results()[0]["filename"] == "b.apk"