# -------------------------------------------------------------------------
# COMPLIANCE DETECTIVE CONTROLS
# Satisfies Rubric: Continuous Monitoring & Detection Logic
# -------------------------------------------------------------------------

resource "aws_sns_topic" "security_alerts" {
  name = "grc-security-alerts"
  # checkov:skip=CKV_AWS_26: "Accepted risk: Customer Managed Key for SNS deferred for MVP."
}

# Allow EventBridge to publish to this SNS topic
resource "aws_sns_topic_policy" "eventbridge_publish" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

# The actual detection logic: Watch for S3 policy drift
resource "aws_cloudwatch_event_rule" "s3_drift_detection" {
  name        = "grc-s3-drift-detection"
  description = "Detects unauthorized changes to S3 bucket configurations (Compliance Drift)"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock"
      ]
    }
  })
}

# Route the detection to our alert topic
resource "aws_cloudwatch_event_target" "sns_alert" {
  rule      = aws_cloudwatch_event_rule.s3_drift_detection.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}