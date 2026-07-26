import asyncio
import urllib.parse

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Intact Network Monitor API")


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


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

    async def process_url(url_to_scan):
        captured_domains = set()
        redirects = []
        errors = []

        context = await browser.new_context(viewport={"width": 1366, "height": 768})
        page = await context.new_page()
        page.set_default_timeout(60000)

        def handle_request(req):
            domain = urllib.parse.urlparse(req.url).netloc
            if domain:
                captured_domains.add(domain)

        def handle_response(resp):
            if resp.request.is_navigation_request():
                status = resp.status
                if status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "unknown")
                    redirects.append((resp.url, location, status))

        page.on("request", handle_request)
        page.on("response", handle_response)

        status_code = 0
        try:
            response = await page.goto(url_to_scan, wait_until="networkidle")
            status_code = response.status if response else 0
            if not response:
                errors.append("No response received")
            elif response.status >= 400:
                errors.append(f"HTTP {response.status}")
        except Exception as e:
            status_code = 0
            errors.append(f"{type(e).__name__}: {e}")
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
