"""CLI runner for Drop-In Zero Trust Reverse Proxy Gateway."""

from __future__ import annotations

import argparse
import uvicorn
from app.dropin.config import DropInProxyConfig
from app.dropin.proxy_server import create_dropin_proxy_app


def main():
    parser = argparse.ArgumentParser(
        description="VajraNetra Drop-In Zero Trust Reverse Proxy Gateway",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--upstream",
        type=str,
        default="http://localhost:3000",
        help="Target upstream application URL to protect",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Interface to bind the proxy server",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to run the proxy server on",
    )
    parser.add_argument(
        "--no-inject",
        action="store_true",
        help="Disable automatic HTML browser SDK injection",
    )
    args = parser.parse_args()

    config = DropInProxyConfig(
        default_upstream=args.upstream,
        listen_host=args.host,
        listen_port=args.port,
        enable_html_injection=not args.no_inject,
    )

    print(f"🛡️ Starting VajraNetra Drop-In ZTNA Gateway...")
    print(f"🔗 Protecting Upstream: {config.default_upstream}")
    print(f"🚀 Gateway listening on: http://{config.listen_host}:{config.listen_port}")
    print(f"💉 HTML SDK Injection: {'Enabled' if config.enable_html_injection else 'Disabled'}")

    app = create_dropin_proxy_app(config)
    uvicorn.run(app, host=config.listen_host, port=config.listen_port, log_level="info")


if __name__ == "__main__":
    main()
