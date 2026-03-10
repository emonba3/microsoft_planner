import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy import String, Text, DateTime, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession


def utcnow():
    return datetime.now(timezone.utc)


SQLITE_PATH = os.environ.get("SQLITE_PATH", "./planner_mcp.sqlite3")
DATABASE_URL = f"sqlite+aiosqlite:///{SQLITE_PATH}"


class Base(DeclarativeBase):
    pass


class PlannerConnection(Base):
    __tablename__ = "planner_connections"
    user_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    access_token_enc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token_enc: Mapped[str] = mapped_column(Text, nullable=False)
    access_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def delete_connection(user_id: str, tenant_id: str) -> bool:
    async with AsyncSessionLocal() as session:
        stmt = select(PlannerConnection).where(
            PlannerConnection.user_id == user_id,
            PlannerConnection.tenant_id == tenant_id,
        )
        obj = (await session.execute(stmt)).scalars().first()
        if not obj:
            return False
        await session.delete(obj)
        await session.commit()
        return True


async def upsert_connection(
    user_id: str,
    tenant_id: str,
    tenant_name: Optional[str],
    access_token_enc: Optional[str],
    refresh_token_enc: str,
    access_token_expires_at: Optional[datetime],
) -> None:
    async with AsyncSessionLocal() as session:
        obj = await session.get(PlannerConnection, {"user_id": user_id, "tenant_id": tenant_id})
        if obj is None:
            obj = PlannerConnection(
                user_id=user_id,
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                access_token_enc=access_token_enc,
                refresh_token_enc=refresh_token_enc,
                access_token_expires_at=access_token_expires_at,
                updated_at=utcnow(),
            )
            session.add(obj)
        else:
            if tenant_name:
                obj.tenant_name = tenant_name
            obj.access_token_enc = access_token_enc
            obj.refresh_token_enc = refresh_token_enc
            obj.access_token_expires_at = access_token_expires_at
            obj.updated_at = utcnow()
        await session.commit()


async def list_connections(user_id: str) -> List[Dict[str, Any]]:
    async with AsyncSessionLocal() as session:
        stmt = (
            select(PlannerConnection)
            .where(PlannerConnection.user_id == user_id)
            .order_by(PlannerConnection.updated_at.desc())
        )
        res = await session.execute(stmt)
        rows = res.scalars().all()
        return [
            {
                "tenant_id": r.tenant_id,
                "tenant_name": r.tenant_name,
                "updated_at": r.updated_at.isoformat(),
            }
            for r in rows
        ]


async def get_connection(user_id: str, tenant_id: str) -> Dict[str, Any]:
    async with AsyncSessionLocal() as session:
        obj = await session.get(PlannerConnection, {"user_id": user_id, "tenant_id": tenant_id})
        if not obj:
            raise ValueError("Not connected")
        return {
            "user_id": obj.user_id,
            "tenant_id": obj.tenant_id,
            "tenant_name": obj.tenant_name,
            "access_token_enc": obj.access_token_enc,
            "refresh_token_enc": obj.refresh_token_enc,
            "access_token_expires_at": obj.access_token_expires_at,
            "updated_at": obj.updated_at,
        }
