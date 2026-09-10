# -*- coding: utf-8 -*-
"""P0-2a v2: malware-traffic-analysis.net 年份索引 → 文章 → pcap"""
import os
import re
import urllib.request

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "eval_real")
os.makedirs(OUT, exist_ok=True)


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def download(url, dest, timeout=120):
    if os.path.exists(dest) and os.path.getsize(dest) > 1000:
        print(f"  [已有] {os.path.basename(dest)} ({os.path.getsize(dest)}B)")
        return True
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    print(f"  [完成] {os.path.basename(dest)} ({os.path.getsize(dest)}B)")
    return True


def main():
    # 年份索引（2025 最新完整年）
    for year in ("2025", "2024"):
        idx_url = f"https://www.malware-traffic-analysis.net/{year}/index.html"
        try:
            html = fetch(idx_url)
            arts = []
            for m in re.findall(r'href="([^"]*?\d{2}/\d{2}/index\.html)"', html):
                if m not in arts:
                    arts.append(m)
            print(f"=== {year} 索引: {len(arts)} 篇文章，最新 {arts[:3]} ===")
            if not arts:
                continue
            # 抓最新 3 篇文章找 pcap
            got = 0
            for a in arts:
                if got >= 2:
                    break
                art_dir = a.rsplit('/', 1)[0] + '/'  # '08/20/'
                art_url = f"https://www.malware-traffic-analysis.net/{year}/{art_dir}"
                try:
                    art_html = fetch(art_url)
                    pcaps = re.findall(r'href="([^"]+\.pcap(?:\.zip)?)"', art_html)
                    if not pcaps:
                        continue
                    for rel in pcaps:
                        if rel.startswith("http"):
                            full = rel
                        elif rel.startswith("/"):
                            full = f"https://www.malware-traffic-analysis.net{rel}"
                        else:
                            full = f"https://www.malware-traffic-analysis.net/{year}/{art_dir}{rel}"
                        name = os.path.basename(rel.split("?")[0])
                        print(f"  文章 {year}/{art_dir} → {name}")
                        download(full, os.path.join(OUT, name))
                        got += 1
                        break  # 每篇只取一个 pcap
                except Exception as e:
                    print(f"  文章抓取失败 {art_url}: {e}")
            if got:
                break
        except Exception as e:
            print(f"{year} 索引失败: {e}")

    print("目录内容:", os.listdir(OUT) if os.path.isdir(OUT) else [])


if __name__ == "__main__":
    main()
