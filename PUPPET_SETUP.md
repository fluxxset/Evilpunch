# Puppet Module Setup Guide

## Overview

The Puppet module intercepts requests matching the pattern `/xxx/xt` and automatically extracts cookies from `fluxxset.com/get` using a headless Chrome browser via Playwright.

## Installation

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Playwright browsers

After installing the Python package, you need to install the browser binaries:

```bash
playwright install chromium
```

Or install all browsers:

```bash
playwright install
```

### 3. Verify Installation

Check that Playwright is properly installed:

```bash
playwright --version
```

## How It Works

1. **Request Interception**: When a request matches the pattern `/xxx/xt` (e.g., `/abc/xt`, `/test/xt`), the puppet module is triggered.

2. **Browser Automation**: A headless Chrome browser is launched using Playwright.

3. **Cookie Extraction**: The browser navigates to `https://fluxxset.com/get` and waits for the page to fully load (networkidle state).

4. **Cookie Injection**: All cookies from the fluxxset.com domain are extracted and automatically added to the original request's Cookie header.

5. **Request Forwarding**: The modified request (with cookies) is forwarded to the upstream server.

## URL Pattern Matching

The module matches URLs with the following pattern:
- `/[anything]/xt`

Examples of matching URLs:
- `/abc/xt`
- `/test/xt`
- `/user123/xt`
- `/my-page/xt`

Examples of non-matching URLs:
- `/abc/xt/more` (additional path segments)
- `/abc/xy` (wrong suffix)
- `/xt` (no prefix)

## Debug Logging

The module includes debug logging with the `[PUPPET]` prefix. You can monitor the following:

1. **Pattern Match**: `[PUPPET] Matched pattern for URL: /xxx/xt`
2. **Navigation**: `[PUPPET] Navigating to fluxxset.com/get...`
3. **Cookie Extraction**: `[PUPPET] Extracted N cookies from fluxxset.com`
4. **Cookie Storage**: `[PUPPET] Cookies stored in request: ...`
5. **Cookie Injection**: `[PUPPET] Adding extracted cookies to upstream request`

## Troubleshooting

### Playwright Installation Issues

If you encounter errors like "Executable doesn't exist", run:

```bash
playwright install --with-deps chromium
```

This installs system dependencies required for running Chromium.

### Timeout Errors

The default timeout is 30 seconds. If `fluxxset.com/get` takes longer to load, you may see timeout errors. The request will continue without the cookies in this case.

### Permission Issues

If running in a Docker container or restricted environment, you may need to add additional Playwright flags:

```python
browser = await p.chromium.launch(
    headless=True,
    args=['--no-sandbox', '--disable-setuid-sandbox']
)
```

Modify this in `evilpunch/core/puppet.py` line 34.

## Performance Considerations

- **Caching**: Consider implementing cookie caching to avoid launching a browser for every request.
- **Parallel Requests**: Multiple simultaneous `/xxx/xt` requests will each launch their own browser instance.
- **Resource Usage**: Each browser instance consumes ~50-100MB of memory.

## Testing

To test the functionality:

1. Start your Evilpunch server
2. Make a request to any URL matching `/xxx/xt` pattern
3. Check the server logs for `[PUPPET]` messages
4. Verify that cookies are being extracted and injected

Example test:
```bash
curl -v http://your-server:port/test/xt
```

Check the logs to see the Puppet module in action.

## Customization

### Change Target URL

To change the URL from which cookies are extracted, modify line 41 in `evilpunch/core/puppet.py`:

```python
await page.goto('https://your-target-site.com/path', wait_until='networkidle', timeout=30000)
```

### Change URL Pattern

To modify the URL pattern matching, edit line 28 in `evilpunch/core/puppet.py`:

```python
pattern = r'^/your-pattern-here$'
```

Examples:
- `r'^/api/.*'` - Match all URLs starting with /api/
- `r'^/\w+/xt$'` - Match only alphanumeric characters before /xt
- `r'^/special/path$'` - Match exact path only

### Additional Headers

To add more data from the automated browser, modify the cookie extraction section (lines 44-63) in `puppet.py`.

## Security Notes

⚠️ **Important Security Considerations**:

1. The extracted cookies are transmitted in plaintext within the Cookie header
2. Ensure your proxy is running over HTTPS in production
3. The headless browser has access to the internet - ensure proper firewall rules
4. Cookies from fluxxset.com are automatically trusted - validate the source

## License

Part of the Evilpunch project.

