from analyzer.graph import ALL_KINDS, build_dot
from tests.helpers import clean_result


def item(name, libs=(), techniques=()):
    result = clean_result()
    result["libraries"] = [{"name": n, "category": "framework"} for n in libs]
    result["mitre"] = [{"technique_id": t, "confidence": c} for t, c in techniques]
    return {"label": name, "score": 5, "level": "LOW", "result": result}


def test_shared_library_creates_one_node_linked_to_both_apks():
    dot, count = build_dot([item("a.apk", ["AndroidX"]), item("b.apk", ["AndroidX", "OkHttp"])],
                           ["Libraries"], only_shared=True)
    assert count == 1
    assert dot.count("AndroidX") == 1 and "OkHttp" not in dot
    assert dot.count("--") == 2


def test_only_shared_off_shows_everything():
    _, count = build_dot([item("a.apk", ["AndroidX"]), item("b.apk", ["OkHttp"])],
                         ["Libraries"], only_shared=False)
    assert count == 2


def test_single_apk_with_only_shared_has_nothing_to_draw():
    assert build_dot([item("a.apk", ["AndroidX"])], ALL_KINDS, only_shared=True)[1] == 0


def test_low_confidence_techniques_hidden_by_default():
    items = [item("a.apk", techniques=[("T1417.002", "low")]),
             item("b.apk", techniques=[("T1417.002", "low")])]
    assert build_dot(items, ["MITRE techniques"], True)[1] == 0
    assert build_dot(items, ["MITRE techniques"], True, include_low=True)[1] == 1


def test_quotes_in_labels_do_not_break_dot():
    dot, _ = build_dot([item('we"ird.apk', ["AndroidX"])], ["Libraries"], only_shared=False)
    assert 'we"ird' not in dot
