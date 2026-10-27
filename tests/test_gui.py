import tkinter as tk

import pytest

from sitecheck import gui, report

from .test_units import fake_result


def test_demo_rows_cover_ok_warn_fail():
    verdicts = {report.verdict(res) for res, _ in gui.demo_rows()}
    assert verdicts == {"OK", "WARN", "FAIL"}


def test_row_values_match_columns():
    for res, _ in gui.demo_rows():
        assert len(gui.row_values(res)) == len(gui.COLUMNS)


def test_row_values_for_failed_check():
    res = fake_result(status=None, ms=None, days=None)
    res["http"]["status"] = None
    assert gui.row_values(res)[2:5] == ("-", "-", "-")


def test_detail_body_has_hints_and_changes():
    res = fake_result()
    body = gui.detail_body(res, [(1000, "a", "issuer", "CA", None)])
    assert "FIX HINTS" in body and "Strict-Transport-Security" in body
    assert "RECENT CHANGES" in body and "issuer: CA -> -" in body
    assert "FIX HINTS" not in gui.detail_body(gui.demo_rows()[0][0])


def test_detail_body_skips_hints_without_response():
    res = fake_result(status=None, ms=None)
    res["http"]["status"] = None
    assert "FIX HINTS" not in gui.detail_body(res)


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    r.withdraw()
    yield r
    r.destroy()


def test_window_lists_demo_sites(root):
    app = gui.App(root, None, demo=True)
    assert len(app.tree.get_children()) == len(gui.demo_rows())
    assert app.tree.selection() == ("0",)
    assert "blog" in app.text.get("1.0", "end")
    app.tree.selection_set("3")
    root.update()
    assert "status" in app.text.get("1.0", "end").splitlines()[0]
