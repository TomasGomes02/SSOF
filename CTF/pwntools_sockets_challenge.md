# Challenge `PwnTools Sockets` writeup

- Vulnerability: Stateful TCP service

- Where: Port 25055 TCP service

- Impact: Allows unlimited manipulation of counter value via protocol commands

- NOTE: Service provides direct current value feedback in clear text

## Steps to reproduce

1. Connect to TCP socket using pwntools `remote()`
2. Receive initial prompt until "What do you want?" appears
3. Extract TARGET and CURRENT values via regex from welcome message
4. Loop while CURRENT value does not equal TARGET
5. Send "MORE" command followed by newline character
6. Receive updated prompt containing new state
7. Parse new CURRENT value from response text
8. Continue loop until CURRENT matches TARGET
9. Send "FINISH" command to finalize
10. Receive flag from final server response

