import re
import asyncio
import dns.resolver
from aiosmtplib import SMTP

# Tier 1: IETF standard compliant regular expression
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

def validate_syntax(email: str) -> bool:
    return bool(re.match(EMAIL_REGEX, email))

def get_mx_records(domain: str) -> list:
    try:
        # Querying the DNS system for MX records
        records = dns.resolver.resolve(domain, 'MX')
        # Sort MX exchanges by priority order (lowest preference score first)
        mx_list = sorted([str(r.exchange).strip('.') for r in records])
        return mx_list
    except Exception:
        return []

async def verify_smtp(email: str, mx_host: str, timeout: int = 7) -> str:
    """
    Tier 3: Asynchronous SMTP Handshake simulation
    """
    # Standard dummy sender domain that is syntactically clean
    sender = "verifier@academic-assessment.com"
    smtp = None
    try:
        # Standard SMTP connection over Port 25
        smtp = SMTP(hostname=mx_host, port=25, timeout=timeout)
        await smtp.connect()
        
        # EHLO: Identify your system client to the target mail server
        await smtp.ehlo()
        
        # MAIL FROM: Assert origin envelope sender address
        await smtp.mail(sender)
        
        # RCPT TO: Evaluate response parameter for target recipient address
        code, response_msg = await smtp.rcpt(email)
        
        # CRITICAL: Always close connection prior to transmission of 'DATA' phase
        await smtp.quit()
        
        # Interpret status responses
        if code == 250:
            return "Valid"
        elif code in [550, 551, 552, 554]:
            return "Bounce"
        else:
            return "Unknown"
            
    except Exception as err:
        # Handle connection drops, throttling, gray-listing timeouts gracefully
        if smtp and smtp.is_connected:
            try:
                await smtp.quit()
            except:
                pass
        return "Unknown"

async def check_catch_all(mx_host: str, timeout: int = 7) -> bool:
    """
    Evaluates if server is configured as a Catch-All (accepts dead mailboxes)
    """
    fake_email = f"system_test_random_{int(asyncio.get_event_loop().time())}@unknown-domain-test.com"
    try:
        smtp = SMTP(hostname=mx_host, port=25, timeout=timeout)
        await smtp.connect()
        await smtp.ehlo()
        await smtp.mail("verifier@academic-assessment.com")
        code, _ = await smtp.rcpt(fake_email)
        await smtp.quit()
        # If a non-existent random string yields 250 OK, the server is a Catch-All
        return code == 250
    except:
        return False

async def process_single_email(email: str) -> str:
    # Tier 1 execution
    if not validate_syntax(email):
        return "Bounce"
        
    domain = email.split('@')[1]
    
    # Tier 2 execution
    mx_records = get_mx_records(domain)
    if not mx_records:
        return "Bounce"
        
    primary_mx = mx_records[0]
    
    # Check Catch-All configurations to mitigate false positives
    is_catch_all = await check_catch_all(primary_mx)
    if is_catch_all:
        return "Catch-All"
        
    # Tier 3 execution
    return await verify_smtp(email, primary_mx)