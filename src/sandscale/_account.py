# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""The account: Sandscale billing, usage, regions and API keys."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence, Union

from ._transport import Transport, seg
from .admin_models import ApiKey, ApiKeyLimits, ApiKeyList, Billing, Checkout, CreatedApiKey, PlanState, RegionInfo, Usage

Raw = dict[str, Any]


def _body(**fields: Any) -> Raw:
    return {k: v for k, v in fields.items() if v is not None}


class Account:
    """Plan, credits, usage, regions and personal API keys. The server decides every plan and
    price; this class only calls it. Plan changes and API keys need a signed-in person's token."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def _org(self) -> str:
        return seg(self._t.require_org())

    # billing
    def billing(self, *, region: Optional[str] = None) -> Billing:
        """Plan state, the offer in force, the credit balance and the price book."""
        return Billing.from_raw(self._t.request("GET", f"/api/v1/orgs/{self._org()}/sandscale/billing", region=region))

    def change_plan(
        self,
        *,
        plan: str,
        interval: Optional[str] = None,
        seats: Optional[int] = None,
        region: Optional[str] = None,
    ) -> PlanState:
        """Changes a live subscription: an upgrade applies now, a downgrade at the period end."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/sandscale/billing/plan",
            region=region,
            json_body=_body(plan=plan, interval=interval, seats=seats),
        )
        return PlanState.from_raw(raw.get("state") if isinstance(raw.get("state"), dict) else raw)

    def set_overage(self, enabled: bool, *, region: Optional[str] = None) -> PlanState:
        """Turns overage on or off (refused 409 ``overage_not_in_plan`` on Free)."""
        raw = self._t.request(
            "PUT", f"/api/v1/orgs/{self._org()}/sandscale/billing/overage", region=region, json_body={"enabled": enabled}
        )
        return PlanState.from_raw(raw.get("state") if isinstance(raw.get("state"), dict) else raw)

    def cancel_pending_plan_change(self, *, region: Optional[str] = None) -> PlanState:
        """Withdraws a waiting downgrade."""
        raw = self._t.request("DELETE", f"/api/v1/orgs/{self._org()}/sandscale/billing/plan/pending", region=region)
        body: Raw = raw if isinstance(raw, dict) else {}
        state = body.get("state")
        return PlanState.from_raw(state if isinstance(state, dict) else body)

    def checkout(
        self,
        *,
        plan: str,
        interval: str,
        seats: Optional[int] = None,
        region: Optional[str] = None,
    ) -> Checkout:
        """Starts a Checkout session for Pro or Team; open ``url`` to pay."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/sandscale/billing/checkout",
            region=region,
            json_body=_body(plan=plan, interval=interval, seats=seats),
        )
        return Checkout.from_raw(raw)

    # usage and regions
    def usage(self, *, region: Optional[str] = None) -> Usage:
        """The month's usage across every region."""
        return Usage.from_raw(self._t.request("GET", "/api/v1/sandscale/usage", region=region))

    def regions(self) -> list[RegionInfo]:
        """The regions the server lists (public)."""
        raw = self._t.request("GET", "/api/v1/regions")
        return [RegionInfo.from_raw(r) for r in raw.get("regions") or [] if isinstance(r, dict)]

    # API keys
    def list_api_keys(self, *, region: Optional[str] = None) -> ApiKeyList:
        raw = self._t.request("GET", "/api/v1/account/api-keys", region=region)
        limits = raw.get("limits") or {}
        return ApiKeyList(
            api_keys=[ApiKey.from_raw(k) for k in raw.get("api_keys") or []],
            limits=ApiKeyLimits(max_days=limits.get("max_days"), max_active=limits.get("max_active")),
        )

    def create_api_key(
        self,
        *,
        name: str,
        expires_at: Union[datetime, str],
        scopes: Optional[Sequence[str]] = None,
        region: Optional[str] = None,
    ) -> CreatedApiKey:
        """Creates a personal API key. The key itself is shown once, on the returned object
        (not in its ``repr``); store it where it belongs and never log it."""
        when = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        body = _body(name=name, scopes=list(scopes) if scopes is not None else None, expires_at=when)
        return CreatedApiKey.from_raw(self._t.request("POST", "/api/v1/account/api-keys", region=region, json_body=body))

    def rotate_api_key(self, key_id: str, *, overlap_seconds: Optional[int] = None, region: Optional[str] = None) -> CreatedApiKey:
        """Replaces a key; the old one keeps working for ``overlap_seconds``."""
        raw = self._t.request(
            "POST",
            f"/api/v1/account/api-keys/{seg(key_id)}/rotate",
            region=region,
            json_body=_body(overlap_seconds=overlap_seconds),
        )
        return CreatedApiKey.from_raw(raw)

    def delete_api_key(self, key_id: str, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", f"/api/v1/account/api-keys/{seg(key_id)}", region=region)
