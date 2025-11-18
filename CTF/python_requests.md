Vulnerability: Business logic flaw with unlimited state manipulation
Where: /more endpoint
Impact: Allows unrestricted incrementing of value to reach arbitrary target
NOTE: No server-side rate limiting or attempt restrictions implemented
Steps to reproduce:

    Create session and GET /hello endpoint
    Extract TARGET and CURRENT values using regex
    Loop while CURRENT != TARGET
    Send GET request to /more endpoint
    Parse updated CURRENT value from response
    Continue until CURRENT matches TARGET
    GET /finish endpoint to obtain flag
