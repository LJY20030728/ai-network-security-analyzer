"""安全知识库模块"""
from src.knowledge.mitre_attck import get_all_knowledge as get_mitre_knowledge
from src.knowledge.network_fundamentals import get_network_knowledge
from src.knowledge.web_security import get_web_security_knowledge


def get_all_knowledge():
    """获取全部知识条目（MITRE ATT&CK + 网络基础 + Web安全）"""
    mitre_items = get_mitre_knowledge()
    network_items = get_network_knowledge()
    web_items = get_web_security_knowledge()
    return mitre_items + network_items + web_items
