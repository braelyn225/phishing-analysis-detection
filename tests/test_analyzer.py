from phishing_detector.analyzer import analyze_email, analyze_url


def test_analyze_url_low_risk():
    result = analyze_url("https://www.example.com/account/overview")
    assert result.verdict == "low risk"
    assert result.score < 3


def test_analyze_url_high_risk():
    result = analyze_url("http://login.verify-account.example.xyz/secure/update")
    assert result.verdict == "high risk"
    assert result.score >= 6


def test_analyze_email_detects_risk():
    raw_email = (
        "From: Security <security@example.com>\n"
        "Reply-To: alerts@secure-alerts.example.xyz\n"
        "To: user@example.net\n"
        "Subject: Urgent action required - verify your account\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n\n"
        "Please verify your account immediately. "
        "Visit http://login.verify-account.example.xyz/secure/update\n"
    )
    result = analyze_email(raw_email)
    assert result.verdict in {"suspicious", "high risk"}
    assert result.findings


def test_reply_to_same_address_not_flagged():
    raw_email = (
        "From: \"Security Team\" <security@example.com>\n"
        "Reply-To: Security Team <security@example.com>\n"
        "To: user@example.net\n"
        "Subject: Account update\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n\n"
        "Hello.\n"
    )
    result = analyze_email(raw_email)
    assert all(finding.label != "reply_to" for finding in result.findings)


def test_html_only_defanged_url_extracted():
    raw_email = (
        "From: Security <security@example.com>\n"
        "To: user@example.net\n"
        "Subject: =?utf-8?q?Verify_your_account?=\n"
        "Content-Type: text/html; charset=\"utf-8\"\n\n"
        "<html><body>"
        "<p>Verify your account immediately.</p>"
        "<a href=\"hxxp://login[.]verify-account[.]example[.]xyz/secure\">link</a>"
        "</body></html>"
    )
    result = analyze_email(raw_email)
    assert result.findings
