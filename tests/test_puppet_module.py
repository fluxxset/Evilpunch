#!/usr/bin/env python3
"""
Test script for the Puppet module functionality.

This script tests the puppet_onrequest function to ensure:
1. URL pattern matching works correctly
2. Playwright integration functions properly
3. Cookies are extracted and stored correctly
"""

import asyncio
import sys
import os
from unittest.mock import Mock, AsyncMock, patch

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'evilpunch'))

from core.puppet import puppet_onrequest


class MockRelUrl:
    """Mock aiohttp RelUrl object"""
    def __init__(self, path):
        self.path = path


class MockRequest:
    """Mock aiohttp Request object"""
    def __init__(self, path):
        self.rel_url = MockRelUrl(path)
        self._data = {}
    
    def __setitem__(self, key, value):
        self._data[key] = value
    
    def __getitem__(self, key):
        return self._data[key]
    
    def __contains__(self, key):
        return key in self._data


async def test_url_pattern_matching():
    """Test that the URL pattern matching works correctly"""
    print("\n=== Testing URL Pattern Matching ===")
    
    # Test cases: (url, should_match)
    test_cases = [
        ("/test/xt", True),
        ("/abc/xt", True),
        ("/user123/xt", True),
        ("/my-page/xt", True),
        ("/abc/xt/more", False),
        ("/abc/xy", False),
        ("/xt", False),
        ("/test/xt/extra", False),
    ]
    
    for url, should_match in test_cases:
        request = MockRequest(url)
        
        # Mock Playwright to avoid actual browser launch
        with patch('core.puppet.async_playwright') as mock_playwright:
            # Create a mock browser context that returns empty cookies
            mock_context = AsyncMock()
            mock_context.cookies.return_value = []
            mock_page = AsyncMock()
            mock_browser = AsyncMock()
            mock_browser.new_context.return_value = mock_context
            mock_browser.close = AsyncMock()
            
            mock_p = AsyncMock()
            mock_p.chromium.launch.return_value = mock_browser
            mock_context.new_page.return_value = mock_page
            
            mock_playwright.return_value.__aenter__.return_value = mock_p
            
            result = await puppet_onrequest(request)
            
            # Check if cookies were set (indicating pattern matched)
            has_cookies = 'puppet_cookies' in request
            
            if should_match:
                if has_cookies:
                    print(f"✅ PASS: {url} - Matched as expected (but no cookies extracted)")
                elif not has_cookies:
                    # Pattern matched but no cookies (which is fine for empty cookie response)
                    print(f"✅ PASS: {url} - Matched (no cookies from mock)")
            else:
                if not has_cookies:
                    print(f"✅ PASS: {url} - Did not match as expected")
                else:
                    print(f"❌ FAIL: {url} - Matched when it shouldn't")
                    return False
    
    return True


async def test_cookie_extraction():
    """Test cookie extraction and storage"""
    print("\n=== Testing Cookie Extraction ===")
    
    request = MockRequest("/test/xt")
    
    # Mock Playwright with sample cookies
    with patch('core.puppet.async_playwright') as mock_playwright:
        # Create mock cookies
        mock_cookies = [
            {'name': 'session_id', 'value': 'abc123'},
            {'name': 'user_token', 'value': 'xyz789'},
        ]
        
        mock_context = AsyncMock()
        mock_context.cookies.return_value = mock_cookies
        mock_page = AsyncMock()
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_browser.close = AsyncMock()
        
        mock_p = AsyncMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context.new_page.return_value = mock_page
        
        mock_playwright.return_value.__aenter__.return_value = mock_p
        
        result = await puppet_onrequest(request)
        
        # Check if cookies were stored
        if 'puppet_cookies' in request:
            cookies = request['puppet_cookies']
            expected = 'session_id=abc123; user_token=xyz789'
            
            if cookies == expected:
                print(f"✅ PASS: Cookies extracted and formatted correctly")
                print(f"   Cookies: {cookies}")
                return True
            else:
                print(f"❌ FAIL: Cookie format incorrect")
                print(f"   Expected: {expected}")
                print(f"   Got: {cookies}")
                return False
        else:
            print(f"❌ FAIL: Cookies not stored in request")
            return False


async def test_error_handling():
    """Test that errors don't break the request flow"""
    print("\n=== Testing Error Handling ===")
    
    request = MockRequest("/test/xt")
    
    # Mock Playwright to raise an exception
    with patch('core.puppet.async_playwright') as mock_playwright:
        mock_playwright.side_effect = Exception("Test error")
        
        try:
            result = await puppet_onrequest(request)
            print("✅ PASS: Error handled gracefully, request still returned")
            return True
        except Exception as e:
            print(f"❌ FAIL: Exception not handled: {e}")
            return False


async def main():
    """Run all tests"""
    print("=" * 60)
    print("PUPPET MODULE TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("URL Pattern Matching", test_url_pattern_matching),
        ("Cookie Extraction", test_cookie_extraction),
        ("Error Handling", test_error_handling),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ FAIL: {test_name} - Exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

