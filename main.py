import asyncio
import urllib.parse

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Intact Network Monitor API")


async def wait_for_images(page, timeout=5):
    try:
        await page.wait_for_function("""
            () => {
                const imgs = Array.from(document.querySelectorAll('img'));
                return imgs.length > 0 && imgs.every(img => img.complete && img.naturalWidth > 0);
            }
        """, timeout=timeout * 1000)
        return True
    except Exception:
        return False


@app.on_event("startup")
async def startup():
    from cloakbrowser import launch_async
    app.state.browser = await launch_async(
        headless=True,
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
        urls.append(target_arg)
    else:
        body_text = await request.body()
        body_text = body_text.decode("utf-8")
        if body_text:
            urls = [line.strip() for line in body_text.splitlines() if line.strip()]

    if not urls:
        return PlainTextResponse(content="Error: Missing target URLs.\n", status_code=400)

    browser = app.state.browser
    captured_domains = set()

    async def process_url(url_to_scan):
        context = await browser.new_context(viewport={"width": 1366, "height": 768})
        page = await context.new_page()
        page.set_default_timeout(60000)

        def handle_request(request):
            domain = urllib.parse.urlparse(request.url).netloc
            if domain:
                captured_domains.add(domain)

        page.on("request", handle_request)

        try:
            await page.goto(url_to_scan, wait_until="domcontentloaded")
            await wait_for_images(page, timeout=5)
        except Exception:
            pass
        finally:
            await context.close()

    await asyncio.gather(*(process_url(u) for u in urls))

    output = "\n".join(sorted(captured_domains)) + "\n"
    return PlainTextResponse(content=output, status_code=200, media_type="text/plain; charset=utf-8")


@app.post("/", response_class=PlainTextResponse)
async def post_domains(request: Request):
    return await get_domains(request)
