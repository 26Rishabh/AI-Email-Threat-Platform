# ─────────────────────────────────────────────
#  routers/analysis.py
#  REST API endpoints for email analysis.
#
#  ENDPOINTS:
#    POST /api/analyze        — upload .eml, run full analysis, return result
#    GET  /api/analysis/{id}  — fetch a stored analysis by case_id
#    GET  /api/cases          — list all stored cases (most recent first)
#    DELETE /api/analysis/{id}— delete a case
#
#  WHY FastAPI:
#  FastAPI automatically validates request types,
#  handles file uploads cleanly, and generates
#  interactive API docs at /docs — very handy for
#  development and testing.
# ─────────────────────────────────────────────
from fastapi import APIRouter, UploadFile, File, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from datetime import datetime, timezone

from database.connection import get_db
from routers.auth import get_current_user
from modules.email_parser import parse_email
from modules.header_forensics import analyze_headers
from modules.auth_analysis import analyze_authentication
from modules.ai_detection import analyze_email_content, is_model_ready
from modules.url_analysis import analyze_urls
from modules.domain_intel import analyze_domains
from modules.ip_intel import analyze_ips
from modules.correlation import correlate_indicators
from modules.risk_scoring import calculate_risk_score
from modules.evidence import generate_case_id, compute_sha256, build_evidence_record

router = APIRouter(prefix="/api", tags=["Analysis"])


# ── POST /api/analyze ─────────────────────────
@router.post("/analyze", status_code=status.HTTP_201_CREATED)
async def analyze_email(file: UploadFile = File(...),
            username: str = Depends(get_current_user)):
    """
    Main analysis endpoint.

    The frontend sends the .eml file here.
    The backend:
      1. Reads the file bytes
      2. Runs all Phase-1 modules (parsing, headers, auth, evidence)
      3. Stores the result in MongoDB
      4. Returns the full result as JSON

    In later phases, the AI model, URL analysis, IP intelligence,
    and risk scoring will also be called here.
    """
    # ── Validate file type ────────────────────
    filename = file.filename or "unknown.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml files are accepted.",
        )

    # ── Read file bytes ───────────────────────
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # ── Generate case ID + evidence record ────
    case_id  = generate_case_id()
    sha256   = compute_sha256(raw_bytes)
    evidence = build_evidence_record(case_id, filename, sha256, len(raw_bytes))

    # ── Module 1: Parse email ─────────────────
    parsed = parse_email(raw_bytes)

    # ── Module 2: Header forensics ────────────
    header_result = analyze_headers(parsed)

    # ── Module 3: Auth analysis ───────────────
    auth_result = analyze_authentication(parsed)

    # ── Module 4: AI/ML threat detection ──────
    ai_result = analyze_email_content(parsed)

    # ── Module 5: URL analysis ────────────────
    url_result = analyze_urls(parsed)

    # ── Module 6: Domain intelligence ─────────
    from_domain = parsed.get("from_address", "").split("@")[-1] \
                  if "@" in parsed.get("from_address", "") else ""
    domain_result = analyze_domains(
        suspicious_domains=url_result.get("suspicious_domains", []),
        from_domain=from_domain,
    )

    # ── Module 7: IP intelligence ──────────────
    # Combine routing IPs (from headers) + IPs from domain DNS lookups
    all_ips = list(dict.fromkeys(
        header_result.get("routing_ips", []) +
        domain_result.get("all_ips", [])
    ))
    ip_result = analyze_ips(all_ips)

    # ── Module 8: Correlation ─────────────────
    correlation = correlate_indicators(
        header_result, auth_result, ai_result,
        url_result, domain_result, ip_result, parsed,
    )

    # ── Module 9: Risk scoring ────────────────
    risk = calculate_risk_score(
        header_result, auth_result, ai_result,
        url_result, domain_result, ip_result, correlation,
    )

    # ── Assemble analysis document ────────────
    analysis_doc = {
        "case_id":    case_id,
        "username":   username,
        "filename":   filename,
        "evidence":   evidence,

        # Module 1 output
        "email_info": {
            "from_raw":          parsed["from_raw"],
            "from_address":      parsed["from_address"],
            "from_display_name": parsed["from_display_name"],
            "to":                parsed["to"],
            "subject":           parsed["subject"],
            "date":              parsed["date"],
            "reply_to":          parsed["reply_to"],
            "reply_to_address":  parsed["reply_to_address"],
            "return_path":       parsed["return_path"],
            "return_path_address": parsed["return_path_address"],
            "message_id":        parsed["message_id"],
            "x_mailer":          parsed["x_mailer"],
            "x_originating_ip":  parsed["x_originating_ip"],
            "received_headers":  parsed["received_headers"],
            "urls":              parsed["urls"],
            "attachments":       parsed["attachments"],
            "body_plain":        parsed["body_plain"][:2000],
            "file_size_bytes":   parsed["file_size_bytes"],
        },

        # Module 2 output
        "header_forensics": {
            "flags":              header_result["flags"],
            "routing_ips":        header_result["routing_ips"],
            "received_count":     header_result["received_count"],
            "summary":            header_result["summary"],
            "score_contribution": header_result["score_contribution"],
        },

        # Module 3 output
        "authentication": {
            "spf":                    auth_result["spf"],
            "dkim":                   auth_result["dkim"],
            "dmarc":                  auth_result["dmarc"],
            "dkim_signature_present": auth_result["dkim_signature_present"],
            "flags":                  auth_result["flags"],
            "summary":                auth_result["summary"],
            "score_contribution":     auth_result["score_contribution"],
        },

        # Module 4 output
        "ai_detection": {
            "classification":     ai_result["classification"],
            "confidence":         ai_result["confidence"],
            "model_used":         ai_result["model_used"],
            "detected_patterns":  ai_result["detected_patterns"],
            "indicators":         ai_result["indicators"],
            "keyword_score":      ai_result["keyword_score"],
            "explanation":        ai_result["explanation"],
            "score_contribution": ai_result["score_contribution"],
        },

        # Module 5 output
        "url_analysis": {
            "urls_found":         url_result["urls_found"],
            "url_results":        url_result["url_results"],
            "high_risk_urls":     url_result["high_risk_urls"],
            "suspicious_domains": url_result["suspicious_domains"],
            "score_contribution": url_result["score_contribution"],
            "summary":            url_result["summary"],
        },

        # Module 6 output
        "domain_intel": {
            "domains_checked":    domain_result["domains_checked"],
            "domain_results":     domain_result["domain_results"],
            "all_ips":            domain_result["all_ips"],
            "missing_spf":        domain_result["missing_spf"],
            "missing_dmarc":      domain_result["missing_dmarc"],
            "score_contribution": domain_result["score_contribution"],
            "summary":            domain_result["summary"],
        },

        # Module 7 output
        "ip_intel": {
            "ips_investigated":   ip_result["ips_investigated"],
            "ip_results":         ip_result["ip_results"],
            "countries":          ip_result["countries"],
            "isps":               ip_result["isps"],
            "hosting_ips":        ip_result["hosting_ips"],
            "score_contribution": ip_result["score_contribution"],
            "summary":            ip_result["summary"],
        },

        # Module 8 + 9 output
        "correlation": {
            "all_indicators":         correlation["all_indicators"],
            "high_indicator_count":   correlation["high_indicator_count"],
            "total_indicator_count":  correlation["total_indicator_count"],
            "shared_ips":             correlation["shared_ips"],
            "infrastructure_overlap": correlation["infrastructure_overlap"],
            "graph":                  correlation["graph"],
            "summary":                correlation["summary"],
        },

        "risk_score": {
            "score":                  risk["score"],
            "risk_level":             risk["risk_level"],
            "risk_color":             risk["risk_color"],
            "classification":         risk["classification"],
            "ai_confidence":          risk["ai_confidence"],
            "breakdown":              risk["breakdown"],
            "major_reasons":          risk["major_reasons"],
            "total_indicators":       risk["total_indicators"],
            "high_indicators":        risk["high_indicators"],
            "infrastructure_overlap": risk["infrastructure_overlap"],
            "conclusion":             risk["conclusion"],
        },

        "pdf_report_path": None,

        # Metadata
        "status":           "COMPLETE",
        "analysis_version": "3.0.0",
        "ml_model_active":  is_model_ready(),
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }

    # ── Store in MongoDB ──────────────────────
    db = get_db()
    db.analyses.insert_one(analysis_doc)

    # Remove MongoDB's internal _id before returning (not JSON-serializable)
    analysis_doc.pop("_id", None)

    return JSONResponse(content=analysis_doc, status_code=status.HTTP_201_CREATED)


# ── GET /api/analysis/{case_id} ───────────────
@router.get("/analysis/{case_id}")
async def get_analysis(case_id: str,
            username: str = Depends(get_current_user)):
    """
    Retrieves a stored analysis by its Case ID.

    The frontend uses this to load the investigation dashboard.
    """
    db  = get_db()
    doc = db.analyses.find_one({"case_id": case_id,  "username": username}, {"_id": 0})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis found for case ID: {case_id}",
        )
    return doc


# ── GET /api/cases ────────────────────────────
@router.get("/cases")
async def list_cases(limit: int = 20, skip: int = 0,  username: str = Depends(get_current_user)):
    """
    Lists all stored cases, most recent first.

    Used by the frontend to show a history/list of investigations.
    Pagination is supported via 'limit' and 'skip' query parameters.
    """
    db   = get_db()
    docs = list(
        db.analyses.find(
            {"username": username},
            {
                "_id":      0,
                "case_id":  1,
                "filename": 1,
                "email_info.from_address": 1,
                "email_info.subject":      1,
                "authentication.spf":      1,
                "authentication.dkim":     1,
                "authentication.dmarc":    1,
                "risk_score":              1,
                "status":                  1,
                "created_at":              1,
            }
        )
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )
    return {"cases": docs, "total": db.analyses.count_documents({"username": username})}


# ── DELETE /api/analysis/{case_id} ────────────
@router.delete("/analysis/{case_id}", status_code=status.HTTP_200_OK)
async def delete_analysis(case_id: str,
            username: str = Depends(get_current_user)):
    """
    Deletes a case from the database.
    """
    db     = get_db()
    result = db.analyses.delete_one({"case_id": case_id, "username": username})
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No case found with ID: {case_id}",
        )
    return {"message": f"Case {case_id} deleted successfully."}
