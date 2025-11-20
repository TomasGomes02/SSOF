# Challenge `Python requests` writeup

- Vulnerability: No restriction on repeated state manipulation
  
- Where: `/more` endpoint
  
- Impact: Allows unrestricted incrementing of value to reach arbitrary target
  
- NOTE: No server-side rate limiting or attempt restrictions implemented

## Steps to reproduce

1. Create session and GET `/hello` endpoint to initialize state
2. Extract TARGET and CURRENT values using regex patterns
3. Loop while CURRENT value does not equal TARGET
4. Send GET request to `/more` endpoint to increment value
5. Parse updated CURRENT value from response text
6. Continue loop until CURRENT matches TARGET
7. GET `/finish` endpoint to obtain the flag
