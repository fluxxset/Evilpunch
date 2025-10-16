#!/usr/bin/env python3
"""
Diagnostic script to test Playwright installation and browser availability.
"""

import sys
import os
import asyncio

print("=" * 60)
print("PLAYWRIGHT DIAGNOSTIC TEST")
print("=" * 60)

# Test 1: Check if playwright module is installed
print("\n1. Checking if playwright is installed...")
try:
    import playwright
    version = getattr(playwright, '__version__', 'version unknown')
    print(f"   ✅ Playwright module found (version: {version})")
except ImportError as e:
    print(f"   ❌ Playwright not installed: {e}")
    print("   Run: pip install playwright")
    sys.exit(1)

# Test 2: Check playwright.async_api
print("\n2. Checking playwright.async_api...")
try:
    from playwright.async_api import async_playwright
    print(f"   ✅ async_playwright imported successfully")
except ImportError as e:
    print(f"   ❌ Failed to import async_playwright: {e}")
    sys.exit(1)

# Test 3: Try to launch browser
print("\n3. Testing browser launch...")
async def test_browser():
    try:
        print("   - Initializing playwright...")
        async with async_playwright() as p:
            print("   - Playwright initialized")
            
            print("   - Attempting to launch Chromium (headless)...")
            browser = await p.chromium.launch(headless=True)
            print(f"   ✅ Browser launched successfully!")
            
            print("   - Creating browser context...")
            context = await browser.new_context()
            print("   ✅ Context created")
            
            print("   - Creating new page...")
            page = await context.new_page()
            print("   ✅ Page created")
            
            print("   - Navigating to example.com...")
            await page.goto('https://example.com', timeout=15000)
            print(f"   ✅ Navigation successful!")
            print(f"   - Page title: {await page.title()}")
            
            print("   - Closing browser...")
            await browser.close()
            print("   ✅ Browser closed")
            
            return True
    except Exception as e:
        print(f"   ❌ Browser test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Test 4: Check environment
print("\n4. Checking environment...")
print(f"   - Python version: {sys.version}")
print(f"   - Display: {os.environ.get('DISPLAY', 'Not set')}")
print(f"   - XDG_RUNTIME_DIR: {os.environ.get('XDG_RUNTIME_DIR', 'Not set')}")

# Run the async test
print("\n5. Running browser test (this may take a moment)...")
try:
    result = asyncio.run(test_browser())
    if result:
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED - Playwright is working correctly!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ BROWSER TEST FAILED")
        print("=" * 60)
        print("\nPossible solutions:")
        print("1. Install browser binaries: playwright install chromium")
        print("2. Install system dependencies: playwright install-deps chromium")
        print("3. Check if running in Docker/headless environment")
        sys.exit(1)
except Exception as e:
    print(f"\n❌ Test execution failed: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

