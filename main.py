import asyncio
import pyshark
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Packet Capturer")

@mcp.tool()
async def capture_packets(duration: int = 5) -> str:
    capture = pyshark.LiveCapture(interface='Wi-Fi')

    try:
        # 使用 asyncio 的 run_in_executor 避免阻塞主事件迴圈
        await asyncio.get_running_loop().run_in_executor(None, capture.sniff, duration)
        summary = "\n".join(
            f"{pkt.highest_layer} {pkt.ip.src} -> {pkt.ip.dst}"
            for pkt in capture if hasattr(pkt, "ip")
        )
        return summary or "No packets captured."
    except Exception as e:
        return f"Error capturing packets: {e}"

@mcp.tool()
def analyze_pcap(pcap_path: str) -> str:
    import pyshark
    try:
        capture = pyshark.FileCapture(pcap_path)
        protocols = set(pkt.highest_layer for pkt in capture)
        return f"Protocols in PCAP: {', '.join(protocols)}"
    except Exception as e:
        return f"Error analyzing PCAP: {e}"

@mcp.tool()
def extract_credentials(pcap_path: str) -> str:
    import pyshark
    credentials = []
    try:
        capture = pyshark.FileCapture(pcap_path, display_filter="http || ftp || sip")
        for pkt in capture:
            if hasattr(pkt, 'http') and hasattr(pkt.http, 'authorization'):
                credentials.append(f"HTTP Auth: {pkt.http.authorization}")
            elif hasattr(pkt, 'ftp') and hasattr(pkt.ftp, 'request_arg'):
                credentials.append(f"FTP Arg: {pkt.ftp.request_arg}")
            elif hasattr(pkt, 'sip') and hasattr(pkt.sip, 'Authorization'):
                credentials.append(f"SIP Auth: {pkt.sip.Authorization}")
        return "\n".join(credentials) or "No credentials found."
    except Exception as e:
        return f"Error: {e}"

@mcp.tool()
def check_ip_threats(pcap_path: str, blacklist: list[str]) -> str:
    import pyshark
    detected = []
    try:
        capture = pyshark.FileCapture(pcap_path)
        for pkt in capture:
            if hasattr(pkt, "ip") and pkt.ip.dst in blacklist:
                detected.append(f"Threat Detected: {pkt.ip.dst}")
        return "\n".join(detected) or "No threats detected."
    except Exception as e:
        return f"Error: {e}"

@mcp.tool()
def get_summary_stats(pcap_path: str) -> dict:
    import pyshark
    from collections import Counter
    try:
        capture = pyshark.FileCapture(pcap_path)
        protocol_counter = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        for pkt in capture:
            if hasattr(pkt, "ip"):
                src_ips[pkt.ip.src] += 1
                dst_ips[pkt.ip.dst] += 1
            protocol_counter[pkt.highest_layer] += 1
        return {
            "protocols": protocol_counter.most_common(),
            "top_src_ips": src_ips.most_common(5),
            "top_dst_ips": dst_ips.most_common(5),
        }
    except Exception as e:
        return {"error": str(e)}
