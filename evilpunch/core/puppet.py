import re
import asyncio
from playwright.async_api import async_playwright

# Global cache for puppet cookies - stores cookies extracted from browser
_puppet_cookie_cache = {}


async def puppet_onrequest(request):
    """
    Intercept requests matching /xxx/xt pattern and inject cookies from fluxxset.com/get
    
    This function:
    1. Checks if the request URL matches the pattern /xxx/xt
    2. Launches a headless Chrome browser using Playwright
    3. Navigates to fluxxset.com/get
    4. Extracts cookies from the browser
    5. Stores cookies in request for later use
    
    Args:
        request: aiohttp Request object
        
    Returns:
        Modified request object with cookies attached
    """
    # try:
    #     # Get the request URL path
    #     url_path = str(request.rel_url.path)
        
    #     # Check if URL matches pattern /xxx/xt (where xxx can be any characters)
    #     pattern = r'^/[^/]+/xt$'
    #     if "/t/welcome-to-fluxxset/5/4" in url_path :
    #         print("🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆")
    #         print(f"🫆🫆[PUPPET] Matched pattern for URL: {url_path}")
            
    #         # Launch headless Chrome browser using Playwright
    #         async with async_playwright() as p:
    #             print(f"[PUPPET] Launching Chromium browser...")
    #             browser = await p.chromium.launch(
    #                 headless=False,
    #                 args=['--disable-blink-features=AutomationControlled']
    #             )
                
    #             print(f"[PUPPET] Creating browser context...")
    #             context = await browser.new_context(
    #                 viewport={'width': 1280, 'height': 720},
    #                 user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    #             )
                
    #             print(f"[PUPPET] Opening new page...")
    #             try:
    #                 page = await asyncio.wait_for(context.new_page(), timeout=10.0)
    #                 print(f"[PUPPET] Page created successfully!")
    #             except asyncio.TimeoutError:
    #                 print(f"[PUPPET] ERROR: Timeout creating new page after 10 seconds")
    #                 await browser.close()
    #                 return request
    #             except Exception as page_error:
    #                 print(f"[PUPPET] ERROR: Failed to create page: {str(page_error)}")
    #                 import traceback
    #                 traceback.print_exc()
    #                 await browser.close()
    #                 return request
                
    #             print(f"[PUPPET] Navigating to https://fluxxset.com/login ...")
                
    #             try:
    #                 # Navigate to the URL with more flexible wait conditions
    #                 response = await page.goto('https://fluxxset.com/login', wait_until='domcontentloaded', timeout=60000)
    #                 print(f"[PUPPET] Navigation response status: {response.status if response else 'No response'}")
    #                 print(f"[PUPPET] Current URL: {page.url}")
                    
    #                 # Wait a bit more for JavaScript to execute
    #                 print(f"[PUPPET] Waiting for page to settle...")
    #                 await page.wait_for_timeout(3000)  # Wait 3 seconds
                    
    #                 print(f"[PUPPET] Page title: {await page.title()}")
                    
    #             except Exception as nav_error:
    #                 print(f"[PUPPET] Navigation error: {str(nav_error)}")
    #                 import traceback
    #                 traceback.print_exc()
                
    #             # Extract cookies from the browser
    #             print(f"[PUPPET] Extracting cookies...")
    #             cookies = await context.cookies()
    #             print(f"[PUPPET] Extracted {len(cookies)} cookies from fluxxset.com")
                
    #             # Print cookie details for debugging
    #             for cookie in cookies:
    #                 print(f"[PUPPET]   - {cookie['name']}: {cookie['value'][:20]}...")
                
    #             # Keep browser open for a moment to see what happened (for debugging)
    #             print(f"[PUPPET] Keeping browser open for 5 seconds for inspection...")
    #             await page.wait_for_timeout(5000)
                
    #             # Close browser
    #             print(f"[PUPPET] Closing browser...")
    #             await browser.close()
                
    #             # Convert cookies to Cookie header format
    #             if cookies:
    #                 cookie_strings = []
    #                 for cookie in cookies:
    #                     cookie_strings.append(f"{cookie['name']}={cookie['value']}")
                    
    #                 cookie_header = '; '.join(cookie_strings)
                    
    #                 # Store cookies in request object for later use
    #                 # Since aiohttp headers are immutable, we store it as a custom attribute
    #                 request['puppet_cookies'] = cookie_header
                    
    #                 print(f"[PUPPET] Cookies stored in request: {cookie_header[:100]}...")
    #     print("🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆")
    #     return request

        
    # except Exception as e:
    #     # Log error but don't break the request flow
    #     print(f"[PUPPET] Error in puppet_onrequest: {str(e)}")
    #     import traceback
    #     traceback.print_exc()
    #     return request

    pass

async def puppet_onresponse(response):
    """
    Intercept responses when request path is /t/welcome-to-fluxxset/5/4 and inject cookies from fluxxset.com/login
    
    This function:
    1. Checks if the response URL path contains /t/welcome-to-fluxxset/5/4
    2. Launches a headless Chrome browser using Playwright
    3. Navigates to fluxxset.com/login
    4. Extracts cookies from the browser
    5. Stores cookies in response object for injection
    
    Args:
        response: aiohttp ClientResponse object from the target server
        
    Returns:
        Response object with puppet cookies stored for injection
    """
    # try:
    #     print("🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆")
    #     # Get the URL from ClientResponse object
    #     url_path = str(response.url.path) if hasattr(response.url, 'path') else str(response.url)
        
    #     # Check if URL path is /t/welcome-to-fluxxset/5/4
    #     if "/t/welcome-to-fluxxset/5/4" in url_path:
            

    #         print(f"[PUPPET RESPONSE] Matched path /t/welcome-to-fluxxset/5/4 for URL: {url_path}")
            
    #         # Launch headless Chrome browser using Playwright
    #         async with async_playwright() as p:
    #             print(f"[PUPPET RESPONSE] Launching Chromium browser...")
    #             browser = await p.chromium.launch(
    #                 headless=True,  # Run headless for production
    #                 args=[
    #                     '--disable-blink-features=AutomationControlled',
    #                     '--no-sandbox',
    #                     '--disable-setuid-sandbox',
    #                     '--disable-dev-shm-usage',
    #                     '--disable-gpu'
    #                 ]
    #             )
                
    #             print(f"[PUPPET RESPONSE] Creating browser context...")
    #             context = await browser.new_context(
    #                 viewport={'width': 1280, 'height': 720},
    #                 user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    #             )
                
    #             print(f"[PUPPET RESPONSE] Opening new page...")
    #             try:
    #                 page = await context.new_page()  # Remove timeout wrapper - let it use default
    #                 print(f"[PUPPET RESPONSE] Page created successfully!")
    #             except asyncio.TimeoutError:
    #                 print(f"[PUPPET RESPONSE] ERROR: Timeout creating new page after 30 seconds")
    #                 await browser.close()
    #                 return response
    #             except Exception as page_error:
    #                 print(f"[PUPPET RESPONSE] ERROR: Failed to create page: {str(page_error)}")
    #                 import traceback
    #                 traceback.print_exc()
    #                 await browser.close()
    #                 return response
                
    #             print(f"[PUPPET RESPONSE] Navigating to https://fluxxset.com/login ...")
                
    #             try:
    #                 # Navigate to the URL with flexible wait conditions
    #                 nav_response = await page.goto('https://fluxxset.com/login', wait_until='domcontentloaded', timeout=60000)
    #                 print(f"[PUPPET RESPONSE] Navigation response status: {nav_response.status if nav_response else 'No response'}")
    #                 print(f"[PUPPET RESPONSE] Current URL: {page.url}")
                    
    #                 # Wait for page to settle and JavaScript to execute
    #                 print(f"[PUPPET RESPONSE] Waiting for page to settle...")
    #                 await page.wait_for_timeout(3000)  # Wait 3 seconds
                    
    #                 print(f"[PUPPET RESPONSE] Page title: {await page.title()}")
                    
    #             except Exception as nav_error:
    #                 print(f"[PUPPET RESPONSE] Navigation error: {str(nav_error)}")
    #                 import traceback
    #                 traceback.print_exc()
                
    #             # Extract cookies from the browser
    #             print(f"[PUPPET RESPONSE] Extracting cookies...")
    #             cookies = await context.cookies()
    #             print(f"[PUPPET RESPONSE] Extracted {len(cookies)} cookies from fluxxset.com/login")
                
    #             # Print cookie details for debugging
    #             for cookie in cookies:
    #                 print(f"[PUPPET RESPONSE]   - {cookie['name']}: {cookie['value'][:20]}...")
                
    #             # Close browser
    #             print(f"[PUPPET RESPONSE] Closing browser...")
    #             await browser.close()
                
    #             # Convert cookies to the format expected by http_server.py for injection
    #             if cookies:
    #                 puppet_set_cookies = []
    #                 for cookie in cookies:
    #                     # Format each cookie with all attributes
    #                     cookie_data = {
    #                         'name': cookie.get('name', ''),
    #                         'value': cookie.get('value', ''),
    #                         'path': cookie.get('path', '/'),
    #                         'maxAge': cookie.get('maxAge', cookie.get('max_age', 3600)),
    #                         'httpOnly': cookie.get('httpOnly', cookie.get('httponly', False)),
    #                         'secure': cookie.get('secure', False),
    #                         'sameSite': cookie.get('sameSite', cookie.get('samesite', 'Lax'))
    #                     }
    #                     puppet_set_cookies.append(cookie_data)
    #                     print(f"[PUPPET RESPONSE]   Formatted cookie: {cookie_data['name']} = {cookie_data['value'][:20]}...")
                    
    #                 # Store cookies in both the response object AND global cache
    #                 # Response object for direct access, global cache as backup
    #                 response.puppet_set_cookies = puppet_set_cookies
                    
    #                 # Also store in global cache with URL path as key for retrieval
    #                 _puppet_cookie_cache[url_path] = puppet_set_cookies
                    
    #                 print(f"[PUPPET RESPONSE] Stored {len(puppet_set_cookies)} cookies in response object and global cache")
    #                 print(f"[PUPPET RESPONSE] Cookies ready for injection")
        
    #     return response
        
    # except Exception as e:
    #     # Log error but don't break the response flow
    #     print(f"[PUPPET RESPONSE] Error in puppet_onresponse: {str(e)}")
    #     import traceback
    #     traceback.print_exc()
    #     return response
    # print("🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆🫆")
    pass


def get_puppet_cookies(url_path=None, response=None):
    """
    Get puppet cookies from cache or response object for injection.
    
    Args:
        url_path: URL path to look up cookies (optional)
        response: ClientResponse object that may have puppet_set_cookies attached (optional)
    
    Returns:
        List of cookie dicts or None
    """
    # First try to get from response object if provided
    if response and hasattr(response, 'puppet_set_cookies'):
        return response.puppet_set_cookies
    
    # Then try global cache if url_path provided
    if url_path and url_path in _puppet_cookie_cache:
        return _puppet_cookie_cache[url_path]
    
    return None



def inject_puppet_cookies(stream_response, url_path=None, resp=None):
    """
    Inject puppet cookies into the stream response.
    This function does the actual cookie setting - all cookie injection logic is HERE in puppet.py!
    
    Args:
        stream_response: web.StreamResponse object to inject cookies into
        url_path: URL path to look up cookies (optional)
        resp: ClientResponse object that may have cookies attached (optional)
    
    Returns:
        Number of cookies injected
    """
    puppet_cookies = get_puppet_cookies(url_path, resp)
    
    if not puppet_cookies:
        return 0
    
    cookies_injected = 0
    for cookie_data in puppet_cookies:
        try:
            # THIS IS WHERE THE COOKIES ARE SET - right here in puppet.py!
            stream_response.set_cookie(
                name=cookie_data['name'],
                value=cookie_data['value'],
                path=cookie_data.get('path', '/'),
                max_age=cookie_data.get('maxAge', 3600),
                httponly=cookie_data.get('httpOnly', False),
                secure=cookie_data.get('secure', False),
                samesite=cookie_data.get('sameSite', 'Lax')
            )
            cookies_injected += 1
            print(f"[PUPPET] ✅ Injected cookie: {cookie_data['name']}")
        except Exception as e:
            print(f"[PUPPET] ❌ Error injecting cookie {cookie_data['name']}: {e}")
    
    return cookies_injected


def puppet_onerror(error):
    pass

def puppet_oncomplete(complete):
    pass

def puppet_onclose(close):
    pass