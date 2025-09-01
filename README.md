## ✅ 前提：環境変数の定義

```bash
REGION=ap-northeast-1
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TRAIL_NAME=management-events                  # 使用中のTrail名に合わせる
BUCKET_NAME=melon-secret                      # 監視対象のバケット名
RULE_NAME=NotifySlackOnS3AccessRule
LAMBDA_NAME=NotifySlackOnGetObject
ROLE_ARN=arn:aws:iam::806061570917:role/service-role/NotifySlackOnGetObject-role-5j2pzme2
SLACK_WEBHOOK_URL="<https://hooks.slack.com/services/XXX/YYY/ZZZ>"

```

---

## 1. CloudTrailでGetObjectイベントを有効化

```bash
aws cloudtrail put-event-selectors \\
  --trail-name "$TRAIL_NAME" \\
  --event-selectors '[
    {
      "ReadWriteType": "ReadOnly",
      "IncludeManagementEvents": false,
      "DataResources": [
        { "Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::'"$BUCKET_NAME"'/*"] }
      ]
    }
  ]'

```

---

## 2. EventBridgeルールを作成

```bash
aws events put-rule \\
  --name "$RULE_NAME" \\
  --event-pattern "{
    \\"source\\": [\\"aws.s3\\"],
    \\"detail-type\\": [\\"AWS API Call via CloudTrail\\"],
    \\"detail\\": {
      \\"eventSource\\": [\\"s3.amazonaws.com\\"],
      \\"eventName\\": [\\"GetObject\\"],
      \\"requestParameters\\": {\\"bucketName\\": [\\"$BUCKET_NAME\\"]}
    }
  }"

```

---

## 3. Lambdaコードを作成（マスク・人ロボ切り分け処理あり）

```python
import json, os, urllib.parse, urllib.request
from datetime import datetime

SLACK_WEBHOOK_URL = os.environ['SLACK_WEBHOOK_URL']
MASK_IP = os.environ.get('MASK_IP', 'true').lower() == 'true'
MASK_ACCESS_KEY = os.environ.get('MASK_ACCESS_KEY', 'true').lower() == 'true'

def mask_ip(ip: str) -> str:
    if not ip:
        return "-"
    if MASK_IP:
        if ip.count(".") == 3:
            a, b, c, _ = ip.split(".")
            return f"{a}.{b}.{c}.0/24"
        if ":" in ip:
            parts = ip.split(":")
            return ":".join(parts[:4] + ["0000"]*4) + "/64"
    return ip

def mask_access_key(key: str) -> str:
    if MASK_ACCESS_KEY and key:
        return "***" + key[-4:]
    return key or "-"

def mask_arn(arn: str) -> str:
    if not arn or ":" not in arn:
        return arn or "-"
    parts = arn.split(":")
    if len(parts) >= 5:
        parts[4] = "************"
    return ":".join(parts)

def post_to_slack(text: str):
    data = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(SLACK_WEBHOOK_URL, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5): pass

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
    return {"ok": True}

```

---

## 4. Lambda ZIP化

```bash
mkdir -p lambda_s3_getobject
cp app.py lambda_s3_getobject/
zip -j lambda_s3_getobject.zip lambda_s3_getobject/app.py

```

---

## 5. Lambda関数作成

```bash
aws lambda create-function \\
  --function-name "$LAMBDA_NAME" \\
  --region "$REGION" \\
  --runtime python3.11 \\
  --role "$ROLE_ARN" \\
  --handler app.handler \\
  --zip-file fileb://lambda_s3_getobject.zip \\
  --timeout 10 \\
  --memory-size 128 \\
  --environment "Variables={SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL,MASK_IP=true,MASK_ACCESS_KEY=true}"

```

---

## 6. EventBridgeとLambdaを接続（実行許可＋ターゲット登録）

```bash
LAMBDA_ARN=$(aws lambda get-function --region "$REGION" --function-name "$LAMBDA_NAME" --query 'Configuration.FunctionArn' --output text)
RULE_ARN=$(aws events describe-rule --region "$REGION" --name "$RULE_NAME" --query 'Arn' --output text)

aws lambda add-permission \\
  --region "$REGION" \\
  --function-name "$LAMBDA_NAME" \\
  --statement-id allow-events-invoke-from-eb \\
  --action lambda:InvokeFunction \\
  --principal events.amazonaws.com \\
  --source-arn "$RULE_ARN"

aws events put-targets \\
  --region "$REGION" \\
  --rule "$RULE_NAME" \\
  --targets "Id"="t1","Arn"="$LAMBDA_ARN"

```

---

## ✅ テスト

### 1. 任意のS3オブジェクトをGetしてテスト

```bash
aws s3 cp s3://$BUCKET_NAME/sample.txt ./_tmp_test

```

### 2. 手動でLambdaを呼び出すテスト

```bash
aws lambda invoke \\
  --function-name "$LAMBDA_NAME" \\
  --cli-binary-format raw-in-base64-out \\
  --payload '{
    "detail":{
        "eventTime":"2025-08-11T13:00:00Z",
        "requestParameters":{"bucketName":"melon-secret","key":"dummy.txt"},
        "sourceIPAddress":"203.0.113.45",
        "userAgent":"aws-cli/2.27.22",
        "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/test","accessKeyId":"AKIAxxxxxxxxxxxx"},
        "eventName":"GetObject",
        "eventSource":"s3.amazonaws.com",
        "recipientAccountId":"123456789012"
    }
  }' \\
  /dev/stdout

```

---

## 🎯 出力例（Slack）

```
:inbox_tray: *S3 GetObject detected*
- Time: 2025-08-11T13:00:00Z
- Bucket: `melon-secret`
- Key: `dummy.txt`
- IP: `203.0.113.0/24`
- UserAgent: `aws-cli/2.27.22`
- UserIdentity.type: `IAMUser`
- UserIdentity.arn: `arn:aws:iam::************:user/test`
- AccessKeyId: `***WXYZ`
- Event: `GetObject` via `s3.amazonaws.com` (Account `123456789012`)

```

---

![001.jpg](attachment:ac39ff05-9b9f-4ca6-96ba-b1d99e2535a4:001.jpg)

## ✅ 補足

- **CloudWatch Logs** にも `EVENT:` というログ出力が残ります。
- **マスク処理は環境変数でON/OFF切替可能**（`MASK_IP=false` など）。

---
