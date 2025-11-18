# Challenge `Secure by Design` writeup

- Vulnerability: Broken authentication via client-controlled authorization cookie

- Where: Cookie-based user authentication system

- Impact: Privilege escalation by forging unprotected authorization cookie

NOTE: Server uses base64-encoded username without integrity verification

## Steps to reproduce

1. POST login with username "admin" to observe normal behavior
2. Note server sets `user` cookie to base64 encoded "fake-admin"
3. Clear session cookies to start fresh
4. Manually set `user` cookie to base64 encoded "admin" value
5. GET homepage with manipulated cookie in request headers
6. Server grants admin access and returns flag in response
