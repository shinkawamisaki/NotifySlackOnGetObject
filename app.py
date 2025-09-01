import json, os, urllib.parse, urllib.request
from datetime import datetime

SLACK_WEBHOOK_URL = os.environ['SLACK_WEBHOOK_URL']

MASK_IP = os.environ.get('MASK_IP', 'true').lower() == 'true'
MASK_ACCESS_KEY = os.environ.get('MASK_ACCESS_KEY', 'true').lower() == 'true'

def mask_ip(ip: str) -> str:
    if MASK_IP and ip and '.' in ip:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip or "-"

def mask_access_key(key: str) -> str:
    if MASK_ACCESS_KEY and key:
        return "***" + key[-4:]
    return key or "-"

def mask_arn(arn: str) -> str:
    if not arn or ":" not in arn:
        return arn or "-"
    parts = arn.split(":")
    if len(parts) >= 5:
        parts[4] = "************"  # アカウントIDをマスク
    return ":".join(parts)

def post_to_slack(text: str):
    data = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as res:
        res.read()

def is_likely_automated(ui, ua):
    arn = ui.get("arn", "")
    role = arn.split("/")[-2] if "assumed-role/" in arn else ""
    is_ecs = role == "ecsTaskExecutionRole"
    is_sdk = "aws-sdk-go" in (ua or "").lower()
    return ui.get("type") == "AssumedRole" and is_ecs and is_sdk

def handler(event, context):
    print("EVENT:", json.dumps(event))
    d = event.get("detail") or {}
    ev = d.get("eventName")
    src = d.get("eventSource")
    acc = d.get("recipientAccountId")

    et = d.get("eventTime") or datetime.utcnow().isoformat() + "Z"
    ip = mask_ip(d.get("sourceIPAddress"))
    ua = d.get("userAgent") or "-"

    req = d.get("requestParameters") or {}
    bucket = req.get("bucketName")
    key = req.get("key") or (req.get("object") or {}).get("key")
    if key:
        key = urllib.parse.unquote(key)

    ui = d.get("userIdentity") or {}
    utype = ui.get("type")
    uarn  = mask_arn(ui.get("arn") or "-")
    aks   = mask_access_key(ui.get("accessKeyId"))

    is_robot = is_likely_automated(ui, ua)
    prefix = ":robot_face: *S3 GetObject from ECS Task*" if is_robot else ":inbox_tray: *S3 GetObject detected*"

    lines = [
        prefix,
        f"- *Time:* {et}",
        f"- *IP:* `{ip}`",
        f"- *UserAgent:* `{ua}`",
        f"- *UserIdentity.type:* `{utype}`",
        f"- *UserIdentity.arn:* `{uarn}`",
        f"- *AccessKeyId:* `{aks}`",
        f"- *Event:* `{ev}` via `{src}` (Account `{acc}`)"
    ]
    if bucket:
        lines.insert(2, f"- *Bucket:* `{bucket}`")
    if key:
        lines.insert(3, f"- *Key:* `{key}`")

    post_to_slack("\n".join(lines))
    return {"ok": True"}
