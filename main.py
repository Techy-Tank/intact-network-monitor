import asyncio
import os
import urllib.parse

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Intact Network Monitor API")

BOT_CHALLENGE_SIGNALS = [
    "please wait for verification",
    "checking your browser",
    "verify you are human",
    "security check",
    "browser verification",
    "access denied",
    "captcha",
    "challenge-platform",
    "cf-browser-verification",
]


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def parse_proxy(proxy_str):
    if not proxy_str:
        return None
    proxy_str = proxy_str.strip()
    if "@" in proxy_str:
        scheme_host = proxy_str.split("@", 1)
        creds = scheme_host[0]
        host_port = scheme_host[1]
        if "://" in creds:
            proto, user_pass = creds.split("://", 1)
        else:
            proto = "http"
            user_pass = creds
        if ":" in user_pass:
            username, password = user_pass.split(":", 1)
        else:
            username, password = user_pass, ""
        return {
            "server": f"{proto}://{host_port}",
            "username": username,
            "password": password,
        }
    else:
        return {"server": proxy_str}


@app.on_event("startup")
async def startup():
    from cloakbrowser import launch_async
    app.state.browser = await launch_async(
        headless=True,
        humanize=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ],
    )


@app.on_event("shutdown")
async def shutdown():
    await app.state.browser.close()


@app.get("/", response_class=PlainTextResponse)
async def get_domains(request: Request):
    urls = []
    target_arg = request.query_params.get("url")
    proxy_arg = request.query_params.get("proxy") or os.environ.get("DEFAULT_PROXY")

    if target_arg:
        urls.append(normalize_url(target_arg))
    else:
        body_text = await request.body()
        body_text = body_text.decode("utf-8")
        if body_text:
            urls = [normalize_url(line) for line in body_text.splitlines() if line.strip()]

    if not urls:
        return PlainTextResponse(content="Error: Missing target URLs.\n", status_code=400)

    browser = app.state.browser
    results = []
    proxy_config = parse_proxy(proxy_arg)

    async def process_url(url_to_scan):
        captured_domains = set()
        redirects = []
        errors = []
        status_code = 0
        max_retries = 3

        for attempt in range(max_retries):
            captured_domains.clear()
            redirects.clear()
            status_code = 0

            ctx_kwargs = {"viewport": {"width": 1366, "height": 768}}
            if proxy_config:
                ctx_kwargs["proxy"] = proxy_config
            context = await browser.new_context(**ctx_kwargs)
            page = await context.new_page()
            page.set_default_timeout(60000)

            def handle_request(req):
                domain = urllib.parse.urlparse(req.url).netloc
                if domain:
                    captured_domains.add(domain)

            def handle_response(resp):
                if resp.request.is_navigation_request():
                    st = resp.status
                    if st in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "unknown")
                        redirects.append((resp.url, location, st))

            page.on("request", handle_request)
            page.on("response", handle_response)

            try:
                response = await page.goto(url_to_scan, wait_until="networkidle")
                status_code = response.status if response else 0

                if not response:
                    errors.append("No response received")
                    break

                if response.status >= 400:
                    errors.append(f"HTTP {response.status}")
                    break

                await asyncio.sleep(2)

                all_urls = await page.evaluate(
                    "() => performance.getEntriesByType('resource').map(e => e.name)"
                )
                for entry_url in all_urls:
                    domain = urllib.parse.urlparse(entry_url).netloc
                    if domain:
                        captured_domains.add(domain)

                page_text = (await page.content()).lower()
                is_challenge = any(sig in page_text for sig in BOT_CHALLENGE_SIGNALS)

                if not is_challenge:
                    break

                if attempt < max_retries - 1:
                    await asyncio.sleep(3 + attempt * 2)

            except Exception as e:
                status_code = 0
                errors.append(f"{type(e).__name__}: {e}")
                break
            finally:
                await context.close()

        results.append({
            "url": url_to_scan,
            "domains": sorted(captured_domains),
            "redirects": redirects,
            "errors": errors,
            "status_code": status_code,
        })

    await asyncio.gather(*(process_url(u) for u in urls))

    output_lines = []
    for r in results:
        url = r["url"]
        domains = r["domains"]
        redirects = r["redirects"]
        errors = r["errors"]

        header = f"--- {url}"
        if redirects:
            for orig, dest, code in redirects:
                header += f" → {dest} ({code})"
        header += f" | HTTP {r['status_code']} ---"
        output_lines.append(header)

        if errors:
            for e in errors:
                output_lines.append(f"ERROR: {e}")
        else:
            output_lines.append("\n".join(domains))

        output_lines.append("")

    return PlainTextResponse(
        content="\n".join(output_lines),
        status_code=200,
        media_type="text/plain; charset=utf-8",
    )


@app.post("/", response_class=PlainTextResponse)
async def post_domains(request: Request):
    return await get_domains(request)
