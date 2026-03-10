from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app import db
from app.crypto import decrypt, encrypt
from app.planner_graph import graph_get_paged, graph_request, refresh_access_token


async def _resolve_tenant_id(user_id: str, tenant_id: Optional[str]) -> str:
    if tenant_id:
        return tenant_id
    rows = await db.list_connections(user_id)
    if not rows:
        raise ValueError("No Microsoft Planner connection found. Please connect Microsoft 365 Planner in the UI.")
    return rows[0]["tenant_id"]


async def _get_valid_access_token(user_id: str, tenant_id: str) -> str:
    conn = await db.get_connection(user_id, tenant_id)
    expires_at = conn.get("access_token_expires_at")
    access_token_enc = conn.get("access_token_enc")

    if access_token_enc and expires_at and expires_at > datetime.now(timezone.utc) + timedelta(seconds=30):
        return decrypt(access_token_enc)

    refresh_token = decrypt(conn["refresh_token_enc"])
    refreshed = await refresh_access_token(refresh_token)
    access_token = refreshed["access_token"]
    new_refresh_token = refreshed.get("refresh_token", refresh_token)
    expires_in = int(refreshed.get("expires_in", 3600))
    new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    await db.upsert_connection(
        user_id=user_id,
        tenant_id=tenant_id,
        tenant_name=conn.get("tenant_name"),
        access_token_enc=encrypt(access_token),
        refresh_token_enc=encrypt(new_refresh_token),
        access_token_expires_at=new_expires_at,
    )
    return access_token


def _progress_label(percent: Optional[int]) -> str:
    if percent is None:
        return "unknown"
    if percent <= 0:
        return "not_started"
    if percent >= 100:
        return "completed"
    return "in_progress"


async def get_profile(user_id: str, tenant_id: Optional[str]) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    me = await graph_request("GET", "/me", access_token=token)
    return {"tenant_id": tid, "data": me}


async def list_users(user_id: str, tenant_id: Optional[str], *, search: Optional[str] = None, top: int = 50) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    params: Dict[str, Any] = {
        "$top": min(max(top, 1), 999),
        "$select": "id,displayName,givenName,surname,mail,userPrincipalName,jobTitle,officeLocation,mobilePhone,businessPhones",
    }
    headers = None
    if search:
        params["$search"] = f'"displayName:{search}" OR "mail:{search}" OR "userPrincipalName:{search}"'
        params["$count"] = "true"
        headers = {"ConsistencyLevel": "eventual"}
    data = await graph_get_paged("/users", access_token=token, params=params, extra_headers=headers)
    return {"tenant_id": tid, "count": len(data.get("value", [])), "data": data}


async def list_groups(user_id: str, tenant_id: Optional[str], *, search: Optional[str] = None, top: int = 100) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    params: Dict[str, Any] = {
        "$top": min(max(top, 1), 999),
        "$select": "id,displayName,description,mail,mailNickname,groupTypes,visibility",
    }
    headers = None
    if search:
        params["$search"] = f'"displayName:{search}"'
        params["$count"] = "true"
        headers = {"ConsistencyLevel": "eventual"}
    data = await graph_get_paged("/groups", access_token=token, params=params, extra_headers=headers)
    groups = [g for g in data.get("value", []) if "Unified" in (g.get("groupTypes") or [])]
    data["value"] = groups
    return {"tenant_id": tid, "count": len(groups), "data": data}


async def get_group(user_id: str, tenant_id: Optional[str], *, group_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_request(
        "GET",
        f"/groups/{group_id}",
        access_token=token,
        params={"$select": "id,displayName,description,mail,mailNickname,groupTypes,visibility"},
    )
    return {"tenant_id": tid, "group_id": group_id, "data": data}


async def list_group_members(user_id: str, tenant_id: Optional[str], *, group_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_get_paged(
        f"/groups/{group_id}/members/microsoft.graph.user",
        access_token=token,
        params={"$select": "id,displayName,mail,userPrincipalName,jobTitle"},
    )
    return {"tenant_id": tid, "group_id": group_id, "count": len(data.get("value", [])), "data": data}


async def list_group_plans(user_id: str, tenant_id: Optional[str], *, group_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_get_paged(f"/groups/{group_id}/planner/plans", access_token=token)
    return {"tenant_id": tid, "group_id": group_id, "count": len(data.get("value", [])), "data": data}


async def get_plan(user_id: str, tenant_id: Optional[str], *, plan_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_request("GET", f"/planner/plans/{plan_id}", access_token=token)
    return {"tenant_id": tid, "plan_id": plan_id, "data": data}


async def list_plan_buckets(user_id: str, tenant_id: Optional[str], *, plan_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_get_paged("/planner/buckets", access_token=token, params={"$filter": f"planId eq '{plan_id}'"})
    return {"tenant_id": tid, "plan_id": plan_id, "count": len(data.get("value", [])), "data": data}


async def list_plan_tasks(user_id: str, tenant_id: Optional[str], *, plan_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_get_paged(f"/planner/plans/{plan_id}/tasks", access_token=token)
    for t in data.get("value", []):
        t["progressStatus"] = _progress_label(t.get("percentComplete"))
    return {"tenant_id": tid, "plan_id": plan_id, "count": len(data.get("value", [])), "data": data}


async def get_task(user_id: str, tenant_id: Optional[str], *, task_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_request("GET", f"/planner/tasks/{task_id}", access_token=token)
    data["progressStatus"] = _progress_label(data.get("percentComplete"))
    return {"tenant_id": tid, "task_id": task_id, "data": data}


async def get_task_details(user_id: str, tenant_id: Optional[str], *, task_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    data = await graph_request("GET", f"/planner/tasks/{task_id}/details", access_token=token)
    return {"tenant_id": tid, "task_id": task_id, "data": data}


async def get_task_with_details(user_id: str, tenant_id: Optional[str], *, task_id: str) -> Dict[str, Any]:
    task = await get_task(user_id, tenant_id, task_id=task_id)
    details = await get_task_details(user_id, tenant_id, task_id=task_id)
    return {
        "tenant_id": task["tenant_id"],
        "task_id": task_id,
        "task": task["data"],
        "details": details["data"],
    }


async def list_user_tasks(user_id: str, tenant_id: Optional[str], *, target_user_id: str = "me") -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)
    path = "/me/planner/tasks" if target_user_id == "me" else f"/users/{target_user_id}/planner/tasks"
    data = await graph_get_paged(path, access_token=token)
    for t in data.get("value", []):
        t["progressStatus"] = _progress_label(t.get("percentComplete"))
    return {"tenant_id": tid, "target_user_id": target_user_id, "count": len(data.get("value", [])), "data": data}


async def get_plan_snapshot(user_id: str, tenant_id: Optional[str], *, plan_id: str) -> Dict[str, Any]:
    tid = await _resolve_tenant_id(user_id, tenant_id)
    token = await _get_valid_access_token(user_id, tid)

    plan = await graph_request("GET", f"/planner/plans/{plan_id}", access_token=token)
    buckets = await graph_get_paged("/planner/buckets", access_token=token, params={"$filter": f"planId eq '{plan_id}'"})
    tasks = await graph_get_paged(f"/planner/plans/{plan_id}/tasks", access_token=token)

    bucket_names = {b["id"]: b.get("name") for b in buckets.get("value", [])}
    progress_summary = {"not_started": 0, "in_progress": 0, "completed": 0, "unknown": 0}
    by_bucket: Dict[str, Dict[str, Any]] = {}
    by_assignee: Dict[str, Dict[str, Any]] = {}

    for task in tasks.get("value", []):
        status = _progress_label(task.get("percentComplete"))
        task["progressStatus"] = status
        progress_summary[status] = progress_summary.get(status, 0) + 1

        bucket_id = task.get("bucketId") or "unbucketed"
        bucket_label = bucket_names.get(bucket_id) or bucket_id
        bucket_entry = by_bucket.setdefault(bucket_label, {"total": 0, "not_started": 0, "in_progress": 0, "completed": 0, "tasks": []})
        bucket_entry["total"] += 1
        bucket_entry[status] = bucket_entry.get(status, 0) + 1
        bucket_entry["tasks"].append({
            "id": task.get("id"),
            "title": task.get("title"),
            "percentComplete": task.get("percentComplete"),
            "progressStatus": status,
            "dueDateTime": task.get("dueDateTime"),
            "priority": task.get("priority"),
            "assignments": task.get("assignments", {}),
        })

        for assignee_id in (task.get("assignments") or {}).keys():
            user_entry = by_assignee.setdefault(assignee_id, {"user_id": assignee_id, "total": 0, "not_started": 0, "in_progress": 0, "completed": 0, "tasks": []})
            user_entry["total"] += 1
            user_entry[status] = user_entry.get(status, 0) + 1
            user_entry["tasks"].append({
                "id": task.get("id"),
                "title": task.get("title"),
                "percentComplete": task.get("percentComplete"),
                "progressStatus": status,
                "bucket": bucket_label,
                "dueDateTime": task.get("dueDateTime"),
            })

    return {
        "tenant_id": tid,
        "plan": plan,
        "buckets": buckets.get("value", []),
        "tasks": tasks.get("value", []),
        "summary": {
            "plan_id": plan_id,
            "plan_title": plan.get("title"),
            "owner": plan.get("owner"),
            "total_tasks": len(tasks.get("value", [])),
            "total_buckets": len(buckets.get("value", [])),
            "progress": progress_summary,
            "by_bucket": by_bucket,
            "by_assignee": by_assignee,
        },
    }


async def get_user_work_progress(
    user_id: str,
    tenant_id: Optional[str],
    *,
    target_user_id: str = "me",
    plan_id: Optional[str] = None,
) -> Dict[str, Any]:
    task_data = await list_user_tasks(user_id, tenant_id, target_user_id=target_user_id)
    tasks = task_data["data"].get("value", [])
    if plan_id:
        tasks = [t for t in tasks if t.get("planId") == plan_id]

    summary = {"not_started": 0, "in_progress": 0, "completed": 0, "unknown": 0}
    for task in tasks:
        status = task.get("progressStatus") or _progress_label(task.get("percentComplete"))
        summary[status] = summary.get(status, 0) + 1

    return {
        "tenant_id": task_data["tenant_id"],
        "target_user_id": target_user_id,
        "plan_id": plan_id,
        "total_tasks": len(tasks),
        "progress": summary,
        "tasks": tasks,
    }
