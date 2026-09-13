# ─────────────────────────────────────────────
#  modules/correlation.py  —  MODULE 8
#  Threat Intelligence & Correlation
#
#  WHY THIS EXISTS:
#  Individual indicators (a suspicious URL, a failed
#  SPF check, a hosting IP) are weak signals alone.
#  But when multiple indicators share infrastructure
#  — e.g. the URL domain and the routing IP both
#  point to the same hosting provider — that is a
#  much stronger signal.
#
#  This module connects the dots between:
#    Email → Domains → IPs → ISP/ASN
#  and identifies shared infrastructure, which is
#  a key technique in real threat intelligence.
# ─────────────────────────────────────────────
from typing import Any


def correlate_indicators(
    header_result:  dict[str, Any],
    auth_result:    dict[str, Any],
    ai_result:      dict[str, Any],
    url_result:     dict[str, Any],
    domain_result:  dict[str, Any],
    ip_result:      dict[str, Any],
    parsed_email:   dict[str, Any],
) -> dict[str, Any]:
    """
    Main entry point for Module 8.

    Collects all indicators from every module and:
      1. Builds a unified indicator list for the dashboard
      2. Finds shared IPs across domains and routing headers
      3. Detects infrastructure overlap (correlation)
      4. Builds the graph data for the investigation graph (Phase 5)

    Returns a correlation report that feeds into the risk scorer.
    """

    # ── 1. Collect all indicators ─────────────
    all_indicators = []

    # From header forensics
    for flag in header_result.get("flags", []):
        all_indicators.append({
            "source":      "header_forensics",
            "flag":        flag["flag"],
            "severity":    flag["severity"],
            "description": flag["description"],
        })

    # From authentication
    for flag in auth_result.get("flags", []):
        all_indicators.append({
            "source":      "authentication",
            "flag":        flag["flag"],
            "severity":    flag["severity"],
            "description": flag["description"],
        })

    # From AI detection
    for indicator in ai_result.get("indicators", []):
        all_indicators.append({
            "source":      "ai_detection",
            "flag":        indicator["category"],
            "severity":    "MEDIUM",
            "description": indicator["description"],
        })

    # From URL analysis
    for url_res in url_result.get("url_results", []):
        for flag in url_res.get("flags", []):
            all_indicators.append({
                "source":      "url_analysis",
                "flag":        flag["flag"],
                "severity":    flag["severity"],
                "description": flag["description"],
                "url":         url_res.get("url", ""),
            })

    # ── 2. Collect all IPs from every source ──
    routing_ips = set(header_result.get("routing_ips", []))
    domain_ips  = set(domain_result.get("all_ips", []))
    all_ips     = routing_ips | domain_ips

    # ── 3. Find shared infrastructure ─────────
    # If routing IPs and domain IPs overlap, the email
    # was routed through the same infrastructure as
    # the suspicious domains — strong correlation signal.
    shared_ips = routing_ips & domain_ips
    infrastructure_overlap = len(shared_ips) > 0

    # ── 4. Count HIGH severity indicators ─────
    high_indicators    = [i for i in all_indicators if i["severity"] == "HIGH"]
    medium_indicators  = [i for i in all_indicators if i["severity"] == "MEDIUM"]

    # ── 5. Build graph nodes and edges ────────
    # This data powers the investigation graph in Phase 5.
    graph = _build_graph(
        parsed_email, url_result, domain_result, ip_result, routing_ips
    )

    # ── 6. Summary ────────────────────────────
    total = len(all_indicators)
    if len(high_indicators) >= 3:
        summary = (
            f"Strong threat correlation: {len(high_indicators)} HIGH severity "
            f"indicators across multiple modules."
        )
    elif len(high_indicators) >= 1:
        summary = (
            f"{len(high_indicators)} HIGH and {len(medium_indicators)} MEDIUM "
            f"severity indicators correlated."
        )
    elif total > 0:
        summary = f"{total} indicator(s) found — low severity overall."
    else:
        summary = "No significant correlated threat indicators."

    if infrastructure_overlap:
        summary += f" Shared infrastructure detected ({len(shared_ips)} IP overlap)."

    return {
        "all_indicators":          all_indicators,
        "high_indicator_count":    len(high_indicators),
        "medium_indicator_count":  len(medium_indicators),
        "total_indicator_count":   total,
        "all_ips":                 list(all_ips),
        "shared_ips":              list(shared_ips),
        "infrastructure_overlap":  infrastructure_overlap,
        "graph":                   graph,
        "summary":                 summary,
    }


def _build_graph(
    parsed_email:  dict,
    url_result:    dict,
    domain_result: dict,
    ip_result:     dict,
    routing_ips:   set,
) -> dict:
    """
    Builds node/edge data for the investigation graph visualization.

    Format used by React Flow / Cytoscape.js in Phase 5:
      nodes: [ { id, label, type, data } ]
      edges: [ { id, source, target, label } ]
    """
    nodes = []
    edges = []
    node_ids = set()

    def add_node(node_id: str, label: str, node_type: str, data: dict = None):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id":    node_id,
                "label": label,
                "type":  node_type,
                "data":  data or {},
            })

    def add_edge(source: str, target: str, label: str = ""):
        edge_id = f"{source}__{target}"
        edges.append({"id": edge_id, "source": source, "target": target, "label": label})

    # Central email node
    email_id = "email_0"
    subject  = parsed_email.get("subject", "Email")[:40]
    add_node(email_id, f"Email: {subject}", "email")

    # From domain node
    from_addr   = parsed_email.get("from_address", "")
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    if from_domain:
        fd_id = f"domain_{from_domain}"
        add_node(fd_id, from_domain, "domain", {"source": "from_header"})
        add_edge(email_id, fd_id, "from")

    # URL and domain nodes
    for url_res in url_result.get("url_results", [])[:8]:
        url     = url_res.get("url", "")
        domain  = url_res.get("domain", "")
        risk    = url_res.get("risk", "")
        if not domain:
            continue
        d_id = f"domain_{domain}"
        add_node(d_id, domain, "domain", {"risk": risk, "url": url})
        add_edge(email_id, d_id, "url")

    # Domain → IP edges from DNS lookups
    for domain, dresult in domain_result.get("domain_results", {}).items():
        d_id = f"domain_{domain}"
        add_node(d_id, domain, "domain")
        for ip in dresult.get("ips", [])[:2]:
            ip_id = f"ip_{ip}"
            add_node(ip_id, ip, "ip")
            add_edge(d_id, ip_id, "resolves_to")

    # Routing IP nodes
    for ip in list(routing_ips)[:3]:
        ip_id = f"ip_{ip}"
        add_node(ip_id, ip, "ip", {"source": "routing"})
        add_edge(email_id, ip_id, "routed_via")

    # IP → ISP nodes
    for ip_res in ip_result.get("ip_results", []):
        ip  = ip_res.get("ip", "")
        isp = ip_res.get("isp", "")
        country = ip_res.get("country", "")
        if ip and isp and isp != "Unknown":
            ip_id  = f"ip_{ip}"
            isp_id = f"isp_{isp[:20]}"
            add_node(ip_id, ip, "ip", {"country": country})
            add_node(isp_id, isp[:30], "isp", {"country": country})
            add_edge(ip_id, isp_id, "hosted_by")

    return {"nodes": nodes, "edges": edges}
