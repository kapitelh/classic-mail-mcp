# Troubleshooting

| Symptom                                           | Check                                                                                                                                                                         |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Service will not start                            | Correct auth mode/config schema, readable secret file, writable data directory, free PORT and PORT+1. Errors intentionally hide values.                                       |
| Docker says permission denied                     | Match LOCAL_UID/LOCAL_GID in .env to the owner of .secrets and .data. Do not make secrets world-readable.                                                                     |
| HTTP returns 401                                  | Verify the MCP bearer token, not the Google client secret. For OAuth, reconnect with the one allowed Google account.                                                          |
| Authentication succeeded, action discovery failed | Use the /mcp path, exact BASE_URL origin, no stale custom Authorization header, and refresh tools after reconnecting. Verify the correct server revision.                     |
| No sending tools                                  | Default is read-only. Enable read-write, restart and refresh discovery.                                                                                                       |
| code_verifier or verifier is not needed           | This implementation uses separate upstream/downstream PKCE pairs. Confirm you deployed the current source, then restart sign-in; old browser transactions cannot be repaired. |
| Invalid redirect URI                              | Google needs YOUR_ORIGIN/oauth/callback. The MCP client redirect is a different URL, validated by the proxy.                                                                  |
| Browser binding mismatch                          | Start OAuth again in the same browser. Cookies must be enabled and preserved by the reverse proxy.                                                                            |
| Login completes, but access is denied             | allowedEmails refers to the Google sign-in identity, not necessarily your mailbox address. Google must report it as verified.                                                 |
| IMAP works, SMTP fails                            | Check app-password requirements, host/port and separate SMTP credentials. Some providers disable SMTP AUTH or block hosting IPs.                                              |
| Sent folder missing/duplicates                    | Configure sentFolder; disable appendSent if the provider already saves messages.                                                                                              |
| read_message reports stale reference              | UIDVALIDITY changed or message moved. Search again; never guess a replacement UID.                                                                                            |
| Empty search result with nextBeforeUid            | Continue paging; each window is bounded to 10,000 UIDs.                                                                                                                       |
| Send is uncertain                                 | Inspect Sent/provider logs. Never retry with a new key automatically.                                                                                                         |
| Cloud Run cannot use Firestore/Secret Manager     | Check the runtime service account, database condition, named database and secret-version permissions. Build identity and runtime identity are different.                      |
| OAuth stops after some days                       | Check Google audience/testing policy, revoked consent and refresh expiration. Reconnect; do not remove PKCE or TLS validation.                                                |

`check_connection` authenticates to both IMAP and SMTP but sends no mail. `npm run verify < .secrets/config.json` is another local, non-sending check after a build. Its output contains account IDs and sanitized status categories.

Include version, deployment mode, operating system and sanitized error category when reporting a problem. Never attach config files, token responses, callback URLs, mailbox content or raw provider logs.

## Message appears empty or exceeds an old read limit

Update to 2.1.0 or later and refresh MCP tools in your client. Empty plain-text alternatives now fall back to HTML conversion. Large messages use MIME-part reads instead of loading all attachments. For long text, follow `nextTextOffset` with `textOffset`; `bodyLimited` explicitly reports a separate safety cap. Attachment-only mail may legitimately have no body text. Encrypted mail and image-only content require separate decryption or OCR tools.

If a download fails partway through, retry the same attachment index and decoded byte offset. Do not concatenate a failed result. See [tool reference](tools.md) for size limits and unknown streamed sizes.
