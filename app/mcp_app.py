from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

from app.request_context import current_user
from app import db
from app.service import (
    get_profile,
    list_users,
    list_groups,
    get_group,
    list_group_members,
    list_group_plans,
    get_plan,
    list_plan_buckets,
    list_plan_tasks,
    get_task,
    get_task_details,
    get_task_with_details,
    list_user_tasks,
    get_plan_snapshot,
    get_user_work_progress,
)

load_dotenv()

mcp = FastMCP("Microsoft 365 Planner MCP Server", stateless_http=True, host="0.0.0.0")


def _user_id() -> str:
    u = current_user.get() or {}
    return (u.get("sub") or u.get("email") or "unknown_user").strip()


@mcp.tool()
async def planner_list_connections() -> dict:
    """List Microsoft 365 tenant connections available to the signed-in user."""
    return {"connections": await db.list_connections(_user_id())}


@mcp.tool()
async def planner_get_my_profile(tenant_id: str | None = None) -> dict:
    """Get the signed-in Microsoft 365 user profile for the connected tenant."""
    return await get_profile(_user_id(), tenant_id)


@mcp.tool()
async def planner_list_users(tenant_id: str | None = None, search: str | None = None, top: int = 50) -> dict:
    """List Microsoft 365 users. Useful for finding a project member and then retrieving their Planner work."""
    return await list_users(_user_id(), tenant_id, search=search, top=top)


@mcp.tool()
async def planner_list_groups(tenant_id: str | None = None, search: str | None = None, top: int = 100) -> dict:
    """List Microsoft 365 groups that can own Planner plans."""
    return await list_groups(_user_id(), tenant_id, search=search, top=top)


@mcp.tool()
async def planner_get_group(group_id: str, tenant_id: str | None = None) -> dict:
    """Get a Microsoft 365 group by ID."""
    return await get_group(_user_id(), tenant_id, group_id=group_id)


@mcp.tool()
async def planner_list_group_members(group_id: str, tenant_id: str | None = None) -> dict:
    """List members of a Microsoft 365 group. Useful for project teams and ownership context."""
    return await list_group_members(_user_id(), tenant_id, group_id=group_id)


@mcp.tool()
async def planner_list_group_plans(group_id: str, tenant_id: str | None = None) -> dict:
    """List all Planner plans under a Microsoft 365 group."""
    return await list_group_plans(_user_id(), tenant_id, group_id=group_id)


@mcp.tool()
async def planner_get_plan(plan_id: str, tenant_id: str | None = None) -> dict:
    """Get a Planner plan by ID."""
    return await get_plan(_user_id(), tenant_id, plan_id=plan_id)


@mcp.tool()
async def planner_list_plan_buckets(plan_id: str, tenant_id: str | None = None) -> dict:
    """List buckets for a Planner plan."""
    return await list_plan_buckets(_user_id(), tenant_id, plan_id=plan_id)


@mcp.tool()
async def planner_list_plan_tasks(plan_id: str, tenant_id: str | None = None) -> dict:
    """List tasks in a Planner plan, including normalized progress status derived from percentComplete."""
    return await list_plan_tasks(_user_id(), tenant_id, plan_id=plan_id)


@mcp.tool()
async def planner_get_task(task_id: str, tenant_id: str | None = None) -> dict:
    """Get a Planner task by ID."""
    return await get_task(_user_id(), tenant_id, task_id=task_id)


@mcp.tool()
async def planner_get_task_details(task_id: str, tenant_id: str | None = None) -> dict:
    """Get Planner task details such as description, checklist, and references."""
    return await get_task_details(_user_id(), tenant_id, task_id=task_id)


@mcp.tool()
async def planner_get_task_with_details(task_id: str, tenant_id: str | None = None) -> dict:
    """Get both the Planner task and its details in one response."""
    return await get_task_with_details(_user_id(), tenant_id, task_id=task_id)


@mcp.tool()
async def planner_list_user_tasks(target_user_id: str = "me", tenant_id: str | None = None) -> dict:
    """List Planner tasks assigned to a user. Use target_user_id='me' for the signed-in user or pass a specific user ID."""
    return await list_user_tasks(_user_id(), tenant_id, target_user_id=target_user_id)


@mcp.tool()
async def planner_get_project_snapshot(plan_id: str, tenant_id: str | None = None) -> dict:
    """Return a full project snapshot for a Planner plan: plan info, buckets, tasks, progress summary, bucket summary, and assignee summary."""
    return await get_plan_snapshot(_user_id(), tenant_id, plan_id=plan_id)


@mcp.tool()
async def planner_get_user_work_progress(target_user_id: str = "me", plan_id: str | None = None, tenant_id: str | None = None) -> dict:
    """Summarize a user's task workload and work-progress status, optionally narrowed to one plan."""
    return await get_user_work_progress(_user_id(), tenant_id, target_user_id=target_user_id, plan_id=plan_id)
