import pytest

from analyzer import ai
from analyzer.correlate import correlate_findings
from tests.helpers import clean_result, finish, trojan_result


@pytest.fixture
def trojan():
    r = finish(trojan_result(), "com.bad.app")
    return r, correlate_findings(r)


def model_up(monkeypatch, answer="ok"):
    calls = []

    def fake_chat(messages):
        calls.append(messages)
        return answer
    monkeypatch.setattr(ai, "ollama_status", lambda: {"available": True, "model": "m", "message": "ready"})
    monkeypatch.setattr(ai, "_chat", fake_chat)
    return calls


def test_context_contains_the_findings(trojan):
    result, corr = trojan
    ctx = ai.build_context(result, corr)
    assert "sms_with_network" in ctx and "T1636.004" in ctx and "evil-c2.ru" in ctx
    assert "staged_payload" in ctx and "RISK SCORE" in ctx


def test_grounding_accepts_real_identifiers(trojan):
    result, corr = trojan
    known = ai.report_tokens(result, corr)
    answer = ("The rule sms_with_network (T1636.004) fits READ_SMS plus the host evil-c2.ru "
              "and IP 185.220.101.4 with a score of %d." % result["risk"]["score"])
    assert ai.check_grounding(answer, known, result["risk"]["score"]) == []


def test_grounding_flags_invented_identifiers(trojan):
    result, corr = trojan
    known = ai.report_tokens(result, corr)
    answer = "It uses T1999 and contacts 9.9.9.9 and evil-bank.com, rule fake_rule, permission SEND_MONEY."
    flagged = ai.check_grounding(answer, known)
    assert {"T1999", "9.9.9.9", "evil-bank.com", "fake_rule", "SEND_MONEY"} <= set(flagged)


def test_grounding_flags_a_wrong_score(trojan):
    result, corr = trojan
    wrong = result["risk"]["score"] - 7
    flagged = ai.check_grounding(f"The risk score is {wrong}.", ai.report_tokens(result, corr),
                                 result["risk"]["score"])
    assert f"score {wrong}" in flagged


def test_summary_uses_the_model_when_available(monkeypatch, trojan):
    result, corr = trojan
    calls = model_up(monkeypatch, "Why: sms_with_network. Check evil-c2.ru.")
    out = ai.summarize(result, corr)
    assert out["source"] == "ai" and out["unverified"] == []
    system = calls[0][0]["content"]
    assert "Use ONLY facts" in system and "evil-c2.ru" in system


def test_summary_flags_hallucinations(monkeypatch, trojan):
    result, corr = trojan
    model_up(monkeypatch, "It talks to T1999 over fake_rule.")
    assert {"T1999", "fake_rule"} <= set(ai.summarize(result, corr)["unverified"])


def test_summary_falls_back_to_template_when_model_is_down(monkeypatch, trojan):
    result, corr = trojan
    monkeypatch.setattr(ai, "ollama_status", lambda: {"available": False, "model": "m", "message": "down"})
    out = ai.summarize(result, corr)
    assert out["source"] == "template" and "sms_with_network" in out["text"] and out["note"] == "down"


def test_summary_falls_back_when_the_request_fails(monkeypatch, trojan):
    result, corr = trojan
    monkeypatch.setattr(ai, "ollama_status", lambda: {"available": True, "model": "m", "message": "ready"})

    def boom(messages):
        raise ai.AIError("timeout")
    monkeypatch.setattr(ai, "_chat", boom)
    out = ai.summarize(result, corr)
    assert out["source"] == "template" and "timeout" in out["note"]


def test_template_summary_for_a_clean_app():
    r = finish(clean_result())
    text = ai.template_summary(r, [])
    assert "No risk indicators" in text


def test_ask_sends_history_and_question(monkeypatch, trojan):
    result, corr = trojan
    calls = model_up(monkeypatch, "Because of sms_with_network.")
    history = [{"role": "user", "content": f"q{i}"} for i in range(10)]
    out = ai.ask(result, corr, "Why is this high risk?", history)
    sent = calls[0]
    assert sent[-1] == {"role": "user", "content": "Why is this high risk?"}
    assert len(sent) == 1 + 6 + 1  # system, last 6 history turns, question
    assert out["unverified"] == []


def test_ask_raises_when_model_gives_nothing(monkeypatch, trojan):
    result, corr = trojan

    def empty(messages):
        raise ai.AIError("empty")
    monkeypatch.setattr(ai, "_chat", empty)
    with pytest.raises(ai.AIError):
        ai.ask(result, corr, "hi")


def test_status_when_ollama_is_not_running(monkeypatch):
    def refuse(path, payload=None, timeout=0):
        raise ai.AIError("refused")
    monkeypatch.setattr(ai, "_http_json", refuse)
    status = ai.ollama_status()
    assert status["available"] is False and "Ollama" in status["message"]


def test_status_when_model_is_missing_or_present(monkeypatch):
    monkeypatch.setattr(ai, "MODEL", "llama3.2:3b")
    monkeypatch.setattr(ai, "_http_json", lambda *a, **k: {"models": [{"name": "other:1b"}]})
    assert "ollama pull llama3.2:3b" in ai.ollama_status()["message"]
    monkeypatch.setattr(ai, "_http_json", lambda *a, **k: {"models": [{"name": "llama3.2:3b"}]})
    assert ai.ollama_status()["available"] is True


def test_links_explanation_is_grounded(monkeypatch):
    pairs = [{"a": "a.apk", "b": "b.apk", "verdict": "strong link",
              "strong": ["shared network indicator: evil-c2.ru"], "weak": ["common libraries: AndroidX"], "note": ""}]
    model_up(monkeypatch, "a.apk and b.apk share evil-c2.ru and also talk to bad-host.ru.")
    out = ai.explain_links(pairs)
    assert out["unverified"] == ["bad-host.ru"]
