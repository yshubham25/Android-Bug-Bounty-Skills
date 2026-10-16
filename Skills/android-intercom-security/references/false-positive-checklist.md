# False Positive Checklist

Before reporting an Intercom vulnerability, verify ALL of these:

1. Is the messenger configured for public visitor access? → Not a vuln
2. Did you test with separate, clean sessions for each account? → Reused sessions invalidate results
3. Was the response a NEW visitor session, not an existing user's data? → Not IDOR
4. Is the conversation you "accessed" one you created yourself? → Not unauthorized access
5. Can the finding be reproduced after fully clearing app data + cookies? → Must be reproducible
6. Is the behavior caused by Intercom SDK design vs the target app's integration? → Report to correct party
7. Did you actually receive ANOTHER USER's private message content? → Core requirement for IDOR
8. Is creating a support conversation expected functionality? → Usually yes
9. Are you confusing a conversation ID with unauthorized access? → IDs alone aren't proof

A successful API response or conversation ID is NOT evidence of a vulnerability.
You need demonstrated cross-account data access to private content.
