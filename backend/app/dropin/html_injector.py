"""HTML Rewriter and Browser SDK Injector for Drop-In Reverse Proxy.

Transparently injects the Zero Trust Client SDK script into any upstream HTML
response before `</head>` or `</body>` without requiring any source code modifications
in the upstream application.
"""

from __future__ import annotations

import re

SDK_SCRIPT_TAG = b'<script src="/__ztna/ztna-sdk.js" defer></script>'
HEAD_CLOSING_TAG = re.compile(rb"</head>", re.IGNORECASE)
BODY_CLOSING_TAG = re.compile(rb"</body>", re.IGNORECASE)
HTML_CLOSING_TAG = re.compile(rb"</html>", re.IGNORECASE)


def inject_sdk_into_html(content_bytes: bytes) -> bytes:
    """Inject `<script src="/__ztna/ztna-sdk.js" defer></script>` into HTML byte string."""
    if not content_bytes or SDK_SCRIPT_TAG in content_bytes:
        return content_bytes

    # 1. Try injecting right before </head>
    match = HEAD_CLOSING_TAG.search(content_bytes)
    if match:
        idx = match.start()
        return content_bytes[:idx] + SDK_SCRIPT_TAG + content_bytes[idx:]

    # 2. Try injecting right before </body>
    match = BODY_CLOSING_TAG.search(content_bytes)
    if match:
        idx = match.start()
        return content_bytes[:idx] + SDK_SCRIPT_TAG + content_bytes[idx:]

    # 3. Try injecting right before </html>
    match = HTML_CLOSING_TAG.search(content_bytes)
    if match:
        idx = match.start()
        return content_bytes[:idx] + SDK_SCRIPT_TAG + content_bytes[idx:]

    # 4. Fallback: append at the end
    return content_bytes + b"\n" + SDK_SCRIPT_TAG
