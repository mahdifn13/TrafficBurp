# Traffic Logger + Repeater Sender

A Burp Suite Community extension that pulls traffic from your **Proxy History**, saves it to a file you control, and lets you fire any saved request straight into **Repeater** — no Pro license, no lost traffic when you close Burp.

## Why

Burp Suite Community doesn't persist projects to disk, so your Proxy History disappears every time you close Burp. This extension gives you a lightweight, human-readable log file (JSON Lines) that survives restarts, plus a fast way to get back into Repeater without re-navigating the target.

## Features

- **Pull-based, not live-capture.** Reads from Burp's own Proxy History on demand (`Sync Now`) or on a timer — it never intercepts traffic itself, so it adds zero overhead to your proxy.
- **You choose the save location.** Nothing is written anywhere until you pick a file.
- **Auto-sync + auto-save timer**, configurable in minutes (default: 10).
- **Always-on deduplication.** Re-syncing never creates duplicate entries, and only newly-seen history items are scanned (fast, even with a large history).
- **No response bodies stored.** Only the request is kept (that's all Repeater needs) plus the response status code as lightweight metadata — keeps the log file small.
- **Scope filtering**: save everything, only in-scope traffic (using Burp's own Target scope), or a custom domain list.
- **Live search** across the *entire* raw request — URL, query params, headers, body — not just the URL column. Great for "which request had this parameter in it?"
- **Row highlighting** (7 colors) that persists across reloads, so you can flag interesting requests for later.
- **Per-entry comments.** Add a note to any request; if set, it becomes the Repeater tab title when you send it.
- **One-click Send to Repeater**, and Export/Load for sharing a log file separately from your main one.

## Requirements

- Burp Suite (Community or Pro)
- [Jython standalone JAR](https://www.jython.org/download)

## Installation

1. Download `TrafficLoggerRepeater.py` from this repo.
2. In Burp: **Extender → Options → Python Environment** → set the path to your Jython standalone JAR.
3. **Extender → Extensions → Add** → Extension type: `Python` → select `TrafficLoggerRepeater.py`.
4. A new **Traffic Logger** tab appears in Burp's main tab bar.

## Usage

1. Click **Choose Log File...** and pick (or create) a `.jsonl` file. Nothing else works until this is set.
2. Click **Sync Now** to pull whatever's currently in Proxy History, or turn on auto-sync in **Settings...** to have it happen automatically.
3. Use the **search bar** to filter down to the requests you care about.
4. Right-click a row to **highlight** it or **add a comment**.
5. Select a row and click **Send to Repeater** (or right-click → Send to Repeater).

### Settings

Click **Settings...** to configure:
- Auto-sync + auto-save interval
- Pull scope: `Save all` / `In-scope only` (uses Burp's Target scope) / `Custom domains`

## File format

The log is plain JSON Lines (`.jsonl`) — one JSON object per line, easy to `grep`, diff, or parse with your own scripts:

```json
{"index": 0, "time": "2026-07-17 14:01:05", "method": "POST", "host": "example.com", "port": 443, "protocol": "https", "url": "https://example.com/api/oauth/callback", "status": "200", "request_b64": "...", "highlight": "NONE", "comment": "", "dedupe_key": "..."}
```

## Notes

- Request bodies are stored in full (base64-encoded) so Repeater always gets an exact replay. Response bodies are never stored.
- Switching to a different log file (e.g. per-target) automatically starts a fresh sync from the beginning of history.

