# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Object storage: buckets, lifecycle, policy and access keys (``POST /api/v1/svc/objects/<Action>``)."""

from __future__ import annotations

import json
from typing import Any, Mapping, Optional, Sequence, Union

from ._transport import Transport
from .admin_models import (
    AccessKey,
    Bucket,
    BucketList,
    CreatedAccessKey,
    DefaultRetention,
    LifecycleRule,
    ObjectsLimits,
)

Raw = dict[str, Any]


def _retention(r: DefaultRetention) -> Raw:
    return {"Mode": r.mode, "Days": r.days}


def _set(body: Raw, **fields: Any) -> Raw:
    for k, v in fields.items():
        if v is not None:
            body[k] = v
    return body


class Objects:
    """Object storage of the organization. Every action is a POST with a JSON body in the
    service's own (PascalCase) names; this class takes snake_case and answers typed models."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def _call(self, action: str, body: Optional[Raw], region: Optional[str]) -> Raw:
        raw = self._t.request("POST", f"/api/v1/svc/objects/{action}", region=region, json_body=body if body is not None else {})
        return raw if isinstance(raw, dict) else {}

    # buckets
    def create_bucket(
        self,
        name: str,
        *,
        versioning: Optional[str] = None,
        object_lock: Optional[bool] = None,
        default_retention: Optional[DefaultRetention] = None,
        content_class: Optional[str] = None,
        data_events: Optional[str] = None,
        presign: Optional[bool] = None,
        allow_unsigned_payload: Optional[bool] = None,
        tags: Optional[Mapping[str, str]] = None,
        client_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Bucket:
        body = _set(
            {"Name": name},
            Versioning=versioning,
            ObjectLock=object_lock,
            DefaultRetention=_retention(default_retention) if default_retention else None,
            ContentClass=content_class,
            DataEvents=data_events,
            Presign=presign,
            AllowUnsignedPayload=allow_unsigned_payload,
            Tags=dict(tags) if tags is not None else None,
            ClientToken=client_token,
        )
        return Bucket.from_raw(self._call("CreateBucket", body, region), self._t.region_of(region))

    def list_buckets(self, *, next_token: Optional[str] = None, max_results: Optional[int] = None, region: Optional[str] = None) -> BucketList:
        raw = self._call("ListBuckets", _set({}, NextToken=next_token, MaxResults=max_results), region)
        r = self._t.region_of(region)
        return BucketList(buckets=[Bucket.from_raw(b, r) for b in raw.get("Buckets") or []], next_token=raw.get("NextToken") or None)

    def get_bucket(self, name: str, *, region: Optional[str] = None) -> Bucket:
        return Bucket.from_raw(self._call("DescribeBucket", {"Name": name}, region), self._t.region_of(region))

    def update_bucket(
        self,
        name: str,
        *,
        versioning: Optional[str] = None,
        object_lock: Optional[bool] = None,
        default_retention: Optional[DefaultRetention] = None,
        clear_default_retention: Optional[bool] = None,
        data_events: Optional[str] = None,
        content_class: Optional[str] = None,
        presign: Optional[bool] = None,
        allow_unsigned_payload: Optional[bool] = None,
        tags: Optional[Mapping[str, str]] = None,
        region: Optional[str] = None,
    ) -> Bucket:
        body = _set(
            {"Name": name},
            Versioning=versioning,
            ObjectLock=object_lock,
            DefaultRetention=_retention(default_retention) if default_retention else None,
            ClearDefaultRetention=clear_default_retention,
            DataEvents=data_events,
            ContentClass=content_class,
            Presign=presign,
            AllowUnsignedPayload=allow_unsigned_payload,
            Tags=dict(tags) if tags is not None else None,
        )
        return Bucket.from_raw(self._call("UpdateBucket", body, region), self._t.region_of(region))

    def delete_bucket(self, name: str, *, region: Optional[str] = None) -> None:
        self._call("DeleteBucket", {"Name": name}, region)

    # lifecycle
    def put_lifecycle(self, name: str, rules: Sequence[LifecycleRule], *, region: Optional[str] = None) -> None:
        self._call("PutBucketLifecycle", {"Name": name, "Rules": [r.to_wire() for r in rules]}, region)

    def get_lifecycle(self, name: str, *, region: Optional[str] = None) -> list[LifecycleRule]:
        raw = self._call("GetBucketLifecycle", {"Name": name}, region)
        return [LifecycleRule.from_raw(r) for r in raw.get("Rules") or []]

    def delete_lifecycle(self, name: str, *, region: Optional[str] = None) -> None:
        self._call("DeleteBucketLifecycle", {"Name": name}, region)

    # policy
    def put_policy(self, name: str, policy: Union[str, Mapping[str, Any]], *, region: Optional[str] = None) -> None:
        text = policy if isinstance(policy, str) else json.dumps(policy)
        self._call("PutBucketPolicy", {"Name": name, "Policy": text}, region)

    def get_policy(self, name: str, *, region: Optional[str] = None) -> str:
        return str(self._call("GetBucketPolicy", {"Name": name}, region).get("Policy") or "")

    def delete_policy(self, name: str, *, region: Optional[str] = None) -> None:
        self._call("DeleteBucketPolicy", {"Name": name}, region)

    # access keys
    def create_access_key(
        self,
        *,
        description: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        permissions: Optional[Sequence[str]] = None,
        buckets: Optional[Sequence[str]] = None,
        prefixes: Optional[Sequence[str]] = None,
        cidrs: Optional[Sequence[str]] = None,
        region: Optional[str] = None,
    ) -> CreatedAccessKey:
        """Creates an access key. The secret access key is shown once, on the returned object
        (not in its ``repr``); store it where it belongs and never log it."""
        body = _set(
            {},
            Description=description,
            ExpiresInDays=expires_in_days,
            Permissions=list(permissions) if permissions is not None else None,
            Buckets=list(buckets) if buckets is not None else None,
            Prefixes=list(prefixes) if prefixes is not None else None,
            CIDRs=list(cidrs) if cidrs is not None else None,
        )
        raw = self._call("CreateAccessKey", body, region)
        key = AccessKey.from_raw(raw.get("AccessKey") or {}, self._t.region_of(region))
        return CreatedAccessKey(access_key=key, secret_access_key=str(raw.get("SecretAccessKey") or ""))

    def list_access_keys(self, *, all: bool = False, region: Optional[str] = None) -> list[AccessKey]:  # noqa: A002
        raw = self._call("ListAccessKeys", {"All": True} if all else {}, region)
        r = self._t.region_of(region)
        return [AccessKey.from_raw(k, r) for k in raw.get("AccessKeys") or []]

    def update_access_key(self, access_key_id: str, status: str, *, region: Optional[str] = None) -> None:
        """Sets the key ``Active`` or ``Inactive``."""
        self._call("UpdateAccessKey", {"AccessKeyId": access_key_id, "Status": status}, region)

    def delete_access_key(self, access_key_id: str, *, region: Optional[str] = None) -> None:
        self._call("DeleteAccessKey", {"AccessKeyId": access_key_id}, region)

    def limits(self, *, region: Optional[str] = None) -> ObjectsLimits:
        raw = self._call("DescribeObjectsLimits", None, region)
        return ObjectsLimits(
            enabled=raw.get("Enabled") is True,
            reason=raw.get("Reason") or None,
            region=str(raw.get("Region") or ""),
            quotas=[
                {"quota_code": q.get("QuotaCode"), "name": q.get("Name"), "value": q.get("Value"), "used": q.get("Used")}
                for q in raw.get("Quotas") or []
            ],
            features={
                str(k): {"available": v.get("Available") is True, "reason": v.get("Reason") or None}
                for k, v in (raw.get("Features") or {}).items()
                if isinstance(v, dict)
            },
            raw=raw,
        )
