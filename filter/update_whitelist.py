#!/usr/bin/env python3
import json
import re
from collections import defaultdict
import argparse
from datetime import datetime, timedelta
import tldextract
from dateutil import parser  # 导入dateutil解析器

QUERYLOG_PATH = "/opt/AdGuardHome/data/querylog.json"
WHITELIST_PATH = "/opt/AdGuardHome/whitelist.txt"
MIN_HITS = 1  # 默认值调整为 1
EXCLUDE_KEYWORDS = []  # 临时禁用排除规则
EXCLUDE_TLDS = []

def is_excluded_domain(domain):
    return False  # 临时禁用排除逻辑

def extract_second_level_domains(data, days=1):
    domain_counts = defaultdict(int)
    cutoff_time = (datetime.utcnow() - timedelta(days=days)).timestamp()
    print(f"分析时间范围: 从 {datetime.fromtimestamp(cutoff_time)} 到现在")
    
    # 添加计数器用于统计
    total_entries = 0
    valid_entries = 0
    time_parse_errors = 0

    for line in data.splitlines():
        total_entries += 1
        try:
            entry = json.loads(line)
            # 使用dateutil.parser解析时间戳
            try:
                entry_time = parser.isoparse(entry["T"]).timestamp()
            except ValueError:
                # 尝试回退到正则表达式处理时区
                try:
                    # 处理时区格式问题
                    time_str = entry["T"]
                    # 移除毫秒部分，简化格式
                    time_str = re.sub(r'(\.\d+)(\+|\-)', r'\2', time_str)
                    # 尝试标准格式
                    entry_time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S%z").timestamp()
                except Exception as e:
                    time_parse_errors += 1
                    if time_parse_errors < 5:  # 只打印前5个错误
                        print(f"时间解析错误 #{time_parse_errors}: {e}, 时间字符串: {entry['T']}")
                    continue

            if entry_time < cutoff_time:
                continue

            valid_entries += 1
            # 从 "QH" 字段获取域名
            full_domain = entry["QH"].rstrip(".")
            ext = tldextract.extract(full_domain)
            second_level_domain = f"{ext.domain}.{ext.suffix}"
            
            # 每100条记录打印一次进度
            if valid_entries % 100 == 0:
                print(f"已处理 {valid_entries} 条有效记录，当前域名: {second_level_domain}")

            domain_counts[second_level_domain] += 1

        except KeyError as e:
            if str(e) in ["'T'", "'QH'"]:
                print(f"警告: 缺少关键字段 {e} (条目: {json.dumps(entry)[:100]}...)")
            continue
        except Exception as e:
            print(f"解析错误: {e}")
            continue
    
    # 打印处理统计信息
    print(f"\n处理统计:")
    print(f"- 总条目数: {total_entries}")
    print(f"- 有效条目数: {valid_entries}")
    print(f"- 时间解析错误: {time_parse_errors}")
    print(f"- 唯一域名数: {len(domain_counts)}")
    
    # 打印前5个最常见的域名
    if domain_counts:
        print("\n最常见的域名:")
        for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {domain}: {count} 次")

    return domain_counts

def generate_whitelist(domains, min_hits):
    return [f"@@||{domain}^" for domain, count in domains.items() if count >= min_hits]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=1)
    parser.add_argument("--min-hits", type=int, default=MIN_HITS)
    args = parser.parse_args()

    print(f"AdGuard白名单生成工具")
    print(f"配置:")
    print(f"- 分析天数: {args.days}")
    print(f"- 最小命中次数: {args.min_hits}")
    
    try:
        with open(QUERYLOG_PATH, "r") as f:
            data = f.read()
        print(f"成功加载日志文件，大小: {len(data)/1024/1024:.2f} MB")
    except Exception as e:
        print(f"错误: 无法读取日志文件 - {e}")
        return
    
    domains = extract_second_level_domains(data, days=args.days)
    whitelist_rules = generate_whitelist(domains, args.min_hits)

    with open(WHITELIST_PATH, "w") as f:
        f.write("\n".join(sorted(whitelist_rules)))

    print(f"\n白名单已更新：{WHITELIST_PATH}（共 {len(whitelist_rules)} 条规则）")

if __name__ == "__main__":
    main()
