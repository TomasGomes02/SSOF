# Challenge `Python requests Again` writeup

- Vulnerability: Client-side control of server attempt limiting mechanism
  
- Where: `/more` endpoint with `remaining_tries` cookie

- Impact: Bypasses attempt restrictions by manipulating client-side cookie

- NOTE: Server trusts client-provided attempt counter value

## Steps to reproduce

1. Create session and GET `/hello` endpoint
2. Extract TARGET and CURRENT values using regex
3. Loop while CURRENT value does not equal TARGET
4. Set `remaining_tries` cookie to "1" before each request
5. Send GET to `/more` endpoint to increment value
6. Parse updated CURRENT value from response
7. Continue loop until CURRENT matches TARGET
8. GET `/finish` endpoint to obtain the flag
