import asyncio
import urllib.parse
import re

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Intact Network Monitor API")


def strip_to_base_domain(url_string):
    """
    Cleans raw network URLs into absolute base domains.
    Strips protocol links, www prefixes, trailing paths, and ports.
    """
    try:
        parsed = urllib.parse.urlparse(url_string)
        domain = parsed.netloc if parsed.netloc else parsed.path

        # Remove active port designations (e.g., localhost:8080)
        domain = domain.split(':')[0]

        # Strip prefixes like www., www2., etc.
        domain = re.sub(r'^www\d*\.', '', domain.lower())

        return domain.strip()
    except Exception:
        return ""


@app.get("/", response_class=PlainTextResponse)
async def get_domains(request: Request):
    """
    API Endpoint returning clean text domains line-by-line.
    Leaves tracking scripts completely un-intercepted to maintain network data quality.
    Only blocks heavy layout media assets (images, fonts, stylesheets, media).
    """
    from cloakbrowser import launch_async

    urls = []
    target_arg = request.query_params.get("url")

    if target_arg:
        urls.append(target_arg)
    else:
        body_text = await request.body()
        body_text = body_text.decode("utf-8")
        if body_text:
            urls = [line.strip() for line in body_text.splitlines() if line.strip()]

    if not urls:
        return PlainTextResponse(
            content="Error: Missing target URLs.\n",
            status_code=400,
        )

    final_unique_domains = set()

    async with await launch_async(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--js-flags='--max-old-space-size=128'",
        ],
    ) as browser:

        async def process_target_url(url_to_scan):
            context = await browser.new_context()
            page = await context.new_page()

            async def media_only_interceptor(route):
                if route.request.resource_type in ["image", "stylesheet", "font", "media"]:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", media_only_interceptor)

            def log_raw_connections(req):
                cleaned_domain = strip_to_base_domain(req.url)
                if cleaned_domain:
                    final_unique_domains.add(cleaned_domain)

            page.on("request", log_raw_connections)

            try:
                await page.goto(url_to_scan, wait_until="commit", timeout=12000)
            except Exception:
                pass
            finally:
                await context.close()

        await asyncio.gather(*(process_target_url(u) for u in urls))

    output_text_buffer = "\n".join(sorted(list(final_unique_domains))) + "\n"

    return PlainTextResponse(
        content=output_text_buffer,
        status_code=200,
        media_type="text/plain; charset=utf-8",
    )


@app.post("/", response_class=PlainTextResponse)
async def post_domains(request: Request):
    """
    POST variant: accepts line-break separated URLs in body.
    """
    return await get_domains(request)
