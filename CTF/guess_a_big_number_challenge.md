# Challenge Guess a Big Number writeup

- Vulnerability: Information disclosure via directional feedback
- Where: /number/{guess} endpoint
- Impact: Allows efficient determination of secret number using binary search instead of brute-force enumeration

NOTE: Server provides clear "Higher"/"Lower" hints that enable algorithmic solving

## Steps to reproduce:

    1. Initialize requests session with server
    2. Set binary search bounds: low=1, high=100000
    3. Loop while low <= high
    4. Calculate midpoint: (low + high) // 2
    5. Send GET request to /number/{guess}
    6. Parse response text
    7. If response contains "Higher": set low = guess + 1
    8. If response contains "Lower": set high = guess - 1
    9. Continue until response contains "SSof" (flag)

