import asyncio
import os
import time
import urllib.parse
from io import BytesIO

import cloudinary.uploader
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from PIL import Image

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

VIEWPORT_PRESETS = {
    "mobile":           {"width": 375,  "height": 812,  "label": "Mobile (iPhone)"},
    "mobile_hd":        {"width": 390,  "height": 844,  "label": "Mobile HD (iPhone 14)"},
    "mobile_full":      {"width": 430,  "height": 932,  "label": "Mobile Full (iPhone 15 Pro Max)"},
    "tablet":           {"width": 768,  "height": 1024, "label": "Tablet (iPad)"},
    "tablet_hd":        {"width": 820,  "height": 1180, "label": "Tablet HD (iPad Air)"},
    "tablet_landscape": {"width": 1024, "height": 768,  "label": "Tablet Landscape"},
    "pc":               {"width": 1366, "height": 768,  "label": "PC (Laptop)"},
    "pc_hd":            {"width": 1920, "height": 1080, "label": "PC HD (1080p)"},
    "pc_full_hd":       {"width": 2560, "height": 1440, "label": "PC Full HD (1440p)"},
    "pc_4k":            {"width": 3840, "height": 2160, "label": "PC 4K (2160p)"},
}
DEFAULT_VIEWPORT = "pc"


def resolve_viewport(preset_or_width=None, height=None):
    if not preset_or_width:
        v = VIEWPORT_PRESETS[DEFAULT_VIEWPORT]
        return {"width": v["width"], "height": v["height"], "preset": DEFAULT_VIEWPORT}

    key = str(preset_or_width).strip().lower()
    if key in VIEWPORT_PRESETS:
        v = VIEWPORT_PRESETS[key]
        return {"width": v["width"], "height": v["height"], "preset": key}

    if "x" in key:
        parts = key.split("x", 1)
        w, h = int(parts[0]), int(parts[1])
    else:
        w = int(key)
        h = int(height) if height else int(w * 0.5625)

    w = max(320, min(w, 3840))
    h = max(320, min(h, 4320))
    return {"width": w, "height": h, "preset": "custom"}


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


def convert_to_avif(png_bytes, quality=80):
    img = Image.open(BytesIO(png_bytes))
    buf = BytesIO()
    img.save(buf, format="AVIF", quality=quality, speed=0)
    return buf.getvalue()


def upload_to_cloudinary(avif_bytes, url):
    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")[:80]
    timestamp = int(time.time())
    public_id = f"intact-monitor/{safe_name}_{timestamp}"
    result = cloudinary.uploader.upload(
        avif_bytes,
        public_id=public_id,
        resource_type="image",
        format="avif",
    )
    return result["secure_url"]


def build_text_output(results):
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

    return "\n".join(output_lines)


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
    viewport_arg = request.query_params.get("viewport")
    viewport_w = request.query_params.get("viewport_width")
    viewport_h = request.query_params.get("viewport_height")
    vp = resolve_viewport(viewport_arg or viewport_w, viewport_h)

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

            ctx_kwargs = {"viewport": {"width": vp["width"], "height": vp["height"]}}
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

    return PlainTextResponse(
        content=build_text_output(results),
        status_code=200,
        media_type="text/plain; charset=utf-8",
    )


@app.post("/", response_class=PlainTextResponse)
async def post_domains(request: Request):
    return await get_domains(request)


@app.get("/screenshot")
async def screenshot_endpoint(request: Request):
    url = request.query_params.get("url")
    proxy_arg = request.query_params.get("proxy") or os.environ.get("DEFAULT_PROXY")
    quality = int(request.query_params.get("quality", "80"))
    viewport_arg = request.query_params.get("viewport")
    viewport_w = request.query_params.get("viewport_width")
    viewport_h = request.query_params.get("viewport_height")
    vp = resolve_viewport(viewport_arg or viewport_w, viewport_h)

    if not url:
        return JSONResponse(content={"error": "Missing url parameter"}, status_code=400)

    url = normalize_url(url)
    browser = app.state.browser
    proxy_config = parse_proxy(proxy_arg)

    ctx_kwargs = {"viewport": {"width": vp["width"], "height": vp["height"]}}
    if proxy_config:
        ctx_kwargs["proxy"] = proxy_config
    context = await browser.new_context(**ctx_kwargs)
    page = await context.new_page()
    page.set_default_timeout(60000)

    try:
        await page.goto(url, wait_until="networkidle")
        await asyncio.sleep(2)
        png_bytes = await page.screenshot(type="png", full_page=False)
    finally:
        await context.close()

    avif_bytes = convert_to_avif(png_bytes, quality)
    screenshot_url = upload_to_cloudinary(avif_bytes, url)

    return JSONResponse(content={
        "url": url,
        "screenshot": screenshot_url,
        "format": "avif",
        "quality": quality,
        "viewport": {"width": vp["width"], "height": vp["height"], "preset": vp["preset"]},
    })


@app.get("/scan")
async def scan_endpoint(request: Request):
    url = request.query_params.get("url")
    proxy_arg = request.query_params.get("proxy") or os.environ.get("DEFAULT_PROXY")
    quality = int(request.query_params.get("quality", "80"))
    viewport_arg = request.query_params.get("viewport")
    viewport_w = request.query_params.get("viewport_width")
    viewport_h = request.query_params.get("viewport_height")
    vp = resolve_viewport(viewport_arg or viewport_w, viewport_h)

    if not url:
        return JSONResponse(content={"error": "Missing url parameter"}, status_code=400)

    url = normalize_url(url)
    browser = app.state.browser
    proxy_config = parse_proxy(proxy_arg)

    captured_domains = set()
    redirects = []
    errors = []
    status_code = 0

    ctx_kwargs = {"viewport": {"width": vp["width"], "height": vp["height"]}}
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
        response = await page.goto(url, wait_until="networkidle")
        status_code = response.status if response else 0

        if response and response.status < 400:
            await asyncio.sleep(2)

            all_urls = await page.evaluate(
                "() => performance.getEntriesByType('resource').map(e => e.name)"
            )
            for entry_url in all_urls:
                domain = urllib.parse.urlparse(entry_url).netloc
                if domain:
                    captured_domains.add(domain)

            png_bytes = await page.screenshot(type="png", full_page=False)
        else:
            png_bytes = await page.screenshot(type="png", full_page=False)
            if response:
                errors.append(f"HTTP {response.status}")
            else:
                errors.append("No response received")
    except Exception as e:
        status_code = 0
        errors.append(f"{type(e).__name__}: {e}")
        png_bytes = b""
    finally:
        await context.close()

    screenshot_url = ""
    if png_bytes:
        avif_bytes = convert_to_avif(png_bytes, quality)
        screenshot_url = upload_to_cloudinary(avif_bytes, url)

    return JSONResponse(content={
        "url": url,
        "domains": sorted(captured_domains),
        "redirects": [{"from": r[0], "to": r[1], "code": r[2]} for r in redirects],
        "status_code": status_code,
        "errors": errors,
        "screenshot": screenshot_url,
        "viewport": {"width": vp["width"], "height": vp["height"], "preset": vp["preset"]},
    })
