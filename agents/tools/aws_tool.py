"""
AWS Tool — queries CloudTrail for IAM activity, GuardDuty findings,
and IAM permission changes.

Designed for T1078.004 (Cloud Account Abuse) and T1098 (Account Manipulation).
Uses boto3-style parameter conventions over httpx to the AWS APIs.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings

logger = structlog.get_logger(__name__)


class AWSQueryInput(BaseModel):
    query_type: Literal[
        "cloudtrail_by_user",
        "iam_policy_changes",
        "guardduty_findings",
        "assume_role_events",
    ] = Field(description="Type of AWS query to run")
    username: str | None = Field(None, description="AWS IAM username or ARN to investigate")
    account_id: str | None = Field(None, description="AWS account ID")
    region: str | None = Field(None, description="AWS region (defaults to config region)")
    hours_back: int = Field(336, description="Look-back window in hours", ge=1, le=8760)


@observe(name="query_aws", as_type="span")
async def aws_query_async(params: AWSQueryInput) -> dict[str, Any]:
    settings = get_settings()
    if not settings.aws_access_key_id:
        return {
            "source_available": False,
            "source": "aws",
            "query_type": params.query_type,
            "error": (
                "AWS is not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env."
            ),
        }

    region = params.region or settings.aws_region
    since = (datetime.now(timezone.utc) - timedelta(hours=params.hours_back)).isoformat()

    try:
        import boto3  # type: ignore[import]

        session = boto3.Session(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=region,
        )

        if params.query_type == "cloudtrail_by_user":
            return _cloudtrail_by_user(session, params.username or "", since)
        if params.query_type == "iam_policy_changes":
            return _iam_policy_changes(session, since)
        if params.query_type == "guardduty_findings":
            return _guardduty_findings(session, params.account_id)
        if params.query_type == "assume_role_events":
            return _assume_role_events(session, params.username or "", since)

    except ImportError:
        return {
            "source_available": False,
            "source": "aws",
            "error": "boto3 not installed. Run: uv pip install -e .",
        }
    except Exception as exc:
        logger.error("aws_query_error", error=str(exc))
        return {"source": "aws", "error": str(exc), "source_available": False}

    return {
        "source_available": False,
        "source": "aws",
        "error": "AWS query_type did not match a handler or returned no payload.",
        "results": [],
    }


def _cloudtrail_by_user(session: Any, username: str, since: str) -> dict[str, Any]:
    ct = session.client("cloudtrail")
    lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": username}]
    paginator = ct.get_paginator("lookup_events")
    events = []
    for page in paginator.paginate(
        LookupAttributes=lookup_attrs,
        StartTime=since,
    ):
        for ev in page["Events"]:
            events.append({
                "EventName": ev.get("EventName"),
                "EventTime": str(ev.get("EventTime")),
                "SourceIPAddress": ev.get("CloudTrailEvent", "{}"),
                "Username": ev.get("Username"),
            })
        if len(events) >= 200:
            break

    high_risk_events = [
        e for e in events
        if e.get("EventName", "") in {
            "CreateUser", "AttachUserPolicy", "AttachRolePolicy",
            "PutUserPolicy", "CreateAccessKey", "DeleteTrail",
            "StopLogging", "AssumeRoleWithWebIdentity",
        }
    ]
    return {
        "source": "aws_cloudtrail",
        "total_events": len(events),
        "high_risk_events": high_risk_events[:10],
        "username": username,
    }


def _iam_policy_changes(session: Any, since: str) -> dict[str, Any]:
    ct = session.client("cloudtrail")
    iam_events = [
        "AttachUserPolicy", "DetachUserPolicy", "AttachRolePolicy",
        "CreatePolicy", "PutUserPolicy", "CreateUser", "CreateRole",
    ]
    events = []
    for event_name in iam_events:
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
            StartTime=since,
        ):
            for ev in page["Events"]:
                events.append({
                    "EventName": ev.get("EventName"),
                    "EventTime": str(ev.get("EventTime")),
                    "Username": ev.get("Username"),
                })
            break  # only first page per event type

    return {
        "source": "aws_cloudtrail",
        "iam_changes": events[:20],
        "total": len(events),
    }


def _guardduty_findings(session: Any, account_id: str | None) -> dict[str, Any]:
    gd = session.client("guardduty")
    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return {"source": "aws_guardduty", "findings": [], "note": "No GuardDuty detector found"}
    detector_id = detectors[0]
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={"Criterion": {"severity": {"Gte": 4}}},
        MaxResults=20,
    ).get("FindingIds", [])
    if not finding_ids:
        return {"source": "aws_guardduty", "findings": [], "count": 0}
    findings_resp = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
    findings = [
        {
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "created": f.get("CreatedAt"),
        }
        for f in findings_resp.get("Findings", [])
    ]
    return {"source": "aws_guardduty", "findings": findings, "count": len(findings)}


def _assume_role_events(session: Any, username: str, since: str) -> dict[str, Any]:
    ct = session.client("cloudtrail")
    paginator = ct.get_paginator("lookup_events")
    events = []
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}],
        StartTime=since,
    ):
        for ev in page["Events"]:
            if username.lower() in str(ev).lower():
                events.append({
                    "EventTime": str(ev.get("EventTime")),
                    "EventName": ev.get("EventName"),
                    "Username": ev.get("Username"),
                })
        if len(events) >= 50:
            break
    return {"source": "aws_cloudtrail", "assume_role_events": events, "count": len(events)}


@tool("query_aws", args_schema=AWSQueryInput)
async def query_aws(
    query_type: str,
    username: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    hours_back: int = 336,
) -> dict[str, Any]:
    """
    Query AWS services for security-relevant activity. Use this tool to:
    - Trace all CloudTrail events for a specific IAM user (query_type='cloudtrail_by_user')
    - Find recent IAM policy changes (new admin policies attached) (query_type='iam_policy_changes')
    - Retrieve active GuardDuty findings above medium severity (query_type='guardduty_findings')
    - Find AssumeRole events (cross-account privilege escalation) (query_type='assume_role_events')

    Always use for T1078.004 (Cloud Account Abuse) and T1098 (Account Manipulation) alerts.
    Default look-back is 14 days for auth events.
    """
    params = AWSQueryInput(
        query_type=query_type,  # type: ignore[arg-type]
        username=username,
        account_id=account_id,
        region=region,
        hours_back=hours_back,
    )
    return await aws_query_async(params)
