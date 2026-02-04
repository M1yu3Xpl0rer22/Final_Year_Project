def get_owasp_category(alert_name):
    """
    Maps ZAP Alert names to 2021 OWASP Top 10 categories.
    Returns tuple (Category Code, Category Name)
    """
    alert = alert_name.lower()
    
    # A01: Broken Access Control
    if any(x in alert for x in ['access control', 'directory browsing', 'traversal', 'file inclusion']):
        return "A01", "Broken Access Control"

    # A02: Cryptographic Failures
    if any(x in alert for x in ['ssl', 'tls', 'crypto', 'password', 'clear text']):
        return "A02", "Cryptographic Failures"

    # A03: Injection
    if any(x in alert for x in ['sql', 'injection', 'command', 'ldap', 'xss']): # XSS is technically A03 in 2021
        return "A03", "Injection"

    # A04: Insecure Design
    if any(x in alert for x in ['design', 'logic']):
        return "A04", "Insecure Design"

    # A05: Security Misconfiguration
    if any(x in alert for x in ['header', 'configuration', 'csrf', 'clickjacking', 'cookie']):
        return "A05", "Security Misconfiguration"

    # A06: Vulnerable and Outdated Components
    if any(x in alert for x in ['outdated', 'version', 'jquery', 'library']):
        return "A06", "Vulnerable Components"

    # A07: Identification and Authentication Failures
    if any(x in alert for x in ['authentication', 'session', 'login', 'auth']):
        return "A07", "Identification Failures"

    # A08: Software and Data Integrity Failures
    if any(x in alert for x in ['integrity', 'deserialization']):
        return "A08", "Software Integrity"

    # A09: Security Logging and Monitoring Failures
    if any(x in alert for x in ['logging', 'monitoring']):
        return "A09", "Logging Failures"

    # A10: Server-Side Request Forgery (SSRF)
    if any(x in alert for x in ['ssrf', 'request forgery']):
        return "A10", "SSRF"

    return "OTH", "Other Vulnerabilities"
