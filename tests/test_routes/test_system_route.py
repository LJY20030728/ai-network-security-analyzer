"""
系统路由单元测试
"""

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


class TestSystemRoutes:
    """系统路由测试类"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.client = TestClient(app)
    
    def test_health_check(self):
        """测试：健康检查接口"""
        response = self.client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded")
    
    def test_root_redirect(self):
        """测试：根路径重定向"""
        response = self.client.get("/", follow_redirects=False)
        # Gradio UI挂载在根路径，应该返回200或重定向
        assert response.status_code in (200, 307, 302)
    
    def test_nonexistent_route(self):
        """测试：不存在的路由返回404（鉴权中间件先拦截未认证请求）"""
        from config.settings import settings
        # 未认证：先被鉴权中间件拦截得到 401（不暴露路由是否存在）
        pre = self.client.get("/api/nonexistent")
        assert pre.status_code == 401
        # 已认证：路由不存在 → 404
        response = self.client.get(
            "/api/nonexistent",
            headers={"X-API-Token": settings.api_auth_token})
        assert response.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
