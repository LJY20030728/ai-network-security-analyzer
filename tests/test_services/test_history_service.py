"""
历史记录服务单元测试

覆盖 src/services/history_service.py：
- 单例语义
- list/get/add/update/clear 的委托与异常包装
- 表格行 / 下拉选项的字段名与底层 schema 一致（曾因字段名不匹配导致 UI 单元格全空）
- update_analysis 的委托链路（曾因 HistoryStore 缺该方法导致重新分析结果静默不落库）

注：本文件原为 @pytest.mark.skip("服务层重构后需要重写")，导致服务层零覆盖，
    正是它本该抓住上述 update_analysis 缺失问题。现按真实接口重写并启用。
"""
import pytest
from unittest.mock import MagicMock

from src.services.history_service import HistoryService, get_history_service
from src.core.exceptions import HistoryNotFoundError, HistoryError


@pytest.fixture
def service():
    """每个测试用独立实例，避免全局单例污染"""
    return HistoryService()


@pytest.fixture
def mock_store():
    """注入到 service._store 的模拟存储"""
    return MagicMock()


class TestSingleton:
    """单例语义"""

    def test_get_history_service_returns_singleton(self, monkeypatch):
        import src.services.history_service as hs
        monkeypatch.setattr(hs, "_history_service", None, raising=False)
        service1 = get_history_service()
        service2 = get_history_service()
        assert service1 is service2


class TestListAnalysis:
    """list_analysis 委托与异常包装"""

    def test_list_empty(self, service, mock_store):
        mock_store.list_analysis.return_value = []
        service._store = mock_store
        assert service.list_analysis() == []

    def test_list_with_data(self, service, mock_store):
        mock_store.list_analysis.return_value = [
            {"id": "a1", "ts": "20260101_120000", "file": "test1.pcap"},
            {"id": "a2", "ts": "20260102_120000", "file": "test2.pcap"},
        ]
        service._store = mock_store
        result = service.list_analysis()
        assert len(result) == 2
        assert result[0]["file"] == "test1.pcap"

    def test_list_wraps_store_exception(self, service, mock_store):
        mock_store.list_analysis.side_effect = RuntimeError("db down")
        service._store = mock_store
        with pytest.raises(HistoryError):
            service.list_analysis()


class TestGetAnalysis:
    """get_analysis 命中与未命中"""

    def test_get_not_found_raises(self, service, mock_store):
        mock_store.list_analysis.return_value = []
        service._store = mock_store
        with pytest.raises(HistoryNotFoundError) as exc_info:
            service.get_analysis("does-not-exist")
        assert "历史记录不存在" in exc_info.value.message

    def test_get_found(self, service, mock_store):
        mock_store.list_analysis.return_value = [
            {"id": "a1", "ts": "20260101_120000", "file": "hit.pcap"},
        ]
        service._store = mock_store
        rec = service.get_analysis("a1")
        assert rec["file"] == "hit.pcap"


class TestUpdateAnalysis:
    """update_analysis 委托链路（回归防护：HistoryStore 曾缺失该方法）"""

    def test_update_delegates_and_returns_bool(self, service, mock_store):
        mock_store.update_analysis.return_value = True
        service._store = mock_store
        assert service.update_analysis("a1", {"html_report": "/tmp/r.html"}) is True
        mock_store.update_analysis.assert_called_once_with("a1", {"html_report": "/tmp/r.html"})

    def test_update_wraps_store_exception(self, service, mock_store):
        mock_store.update_analysis.side_effect = RuntimeError("no such column")
        service._store = mock_store
        with pytest.raises(HistoryError):
            service.update_analysis("a1", {"html_report": "/tmp/r.html"})

    def test_history_store_exposes_update_analysis(self):
        """真实 HistoryStore 必须具备 update_analysis —— gradio_app 的
        '报告丢失后重新分析' 流程直接依赖它，缺失时会被 except 静默吞掉。"""
        from src.api.history_store import HistoryStore
        assert hasattr(HistoryStore, "update_analysis"), (
            "HistoryStore 缺少 update_analysis：重新分析结果将无法落库"
        )

    def test_database_update_analysis_whitelists_columns(self, tmp_path):
        """Database.update_analysis 必须忽略白名单外的列（防 SQL 注入），
        并正确规整布尔/数值类型。"""
        from src.storage.database import Database
        db = Database(str(tmp_path / "t.db"))
        rec = db.add_analysis({"file": "a.pcap", "packets": 10})
        aid = rec["id"]

        # 白名单字段 → 更新成功
        assert db.update_analysis(aid, {"html_report": "/x/r.html", "packets": 99}) is True
        got = db.get_analysis(aid)
        assert got["html_report"] == "/x/r.html"
        assert got["packets"] == 99

        # 非白名单字段 → 被忽略且不抛异常
        assert db.update_analysis(aid, {"id": "hacked", "ts": "1970"}) is False
        still = db.get_analysis(aid)
        assert still["id"] == aid

        # 布尔规整
        db.update_analysis(aid, {"needs_review": True})
        assert db.get_analysis(aid)["needs_review"] in (1, True)

        # 空参数安全返回
        assert db.update_analysis("", {}) is False


class TestTableAndDropdown:
    """UI 展示字段必须与 database.list_analysis 的列名一致"""

    ROW = {
        "id": "a1", "ts": "20260101_120000", "file": "x.pcap",
        "packets": 100, "flows": 20, "bytes": 5000, "alerts": 3,
        "severity": '{"HIGH": 3}', "supervised_verdict": 1,
        "supervised_confidence": 0.9, "hallucination_risk": "low",
        "needs_review": 0, "summary_text": "some summary", "ai_summary": "",
        "html_report": "/r.html",
    }

    def test_table_rows_map_real_columns(self, service, mock_store):
        mock_store.list_analysis.return_value = [self.ROW]
        service._store = mock_store
        rows = service.get_table_rows()
        assert len(rows) == 1
        row = rows[0]
        # [时间, 文件名, 包数, 流数, 告警数, 严重度, 摘要]
        assert row[0] == "20260101_120000"
        assert row[1] == "x.pcap"
        assert row[2] == 100
        assert row[3] == 20
        assert row[4] == 3
        assert row[5] == '{"HIGH": 3}'
        assert row[6].startswith("some summary")

    def test_dropdown_choices_map_real_columns(self, service, mock_store):
        mock_store.list_analysis.return_value = [self.ROW]
        service._store = mock_store
        choices = service.get_dropdown_choices()
        assert choices == ["20260101_120000 | x.pcap"]

    def test_record_by_dropdown_label(self, service, mock_store):
        mock_store.list_analysis.return_value = [self.ROW]
        service._store = mock_store
        rec = service.get_record_by_dropdown_label("20260101_120000 | x.pcap")
        assert rec is not None and rec["id"] == "a1"
        assert service.get_record_by_dropdown_label("nope") is None


class TestChatHistory:
    """对话历史委托"""

    def test_load_chat(self, service, mock_store):
        mock_store.load_chat.return_value = [{"role": "user", "content": "hi"}]
        service._store = mock_store
        assert service.load_chat_history() == [{"role": "user", "content": "hi"}]

    def test_load_chat_swallows_error(self, service, mock_store):
        mock_store.load_chat.side_effect = RuntimeError("boom")
        service._store = mock_store
        assert service.load_chat_history() == []

    def test_add_chat_round_delegates(self, service, mock_store):
        service._store = mock_store
        service.add_chat_round("q", "a")
        mock_store.add_chat_round.assert_called_once_with("q", "a")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
