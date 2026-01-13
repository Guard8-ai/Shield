"""
Shield Django Integration

Middleware and utilities for Django applications.

Usage:
    # settings.py
    MIDDLEWARE = [
        ...
        'shield.integrations.django.ShieldMiddleware',
    ]

    SHIELD_PASSWORD = 'your-secret-password'
    SHIELD_SERVICE = 'your-app.com'

    # views.py
    from shield.integrations.django import shield_protected

    @shield_protected
    def secret_view(request):
        return JsonResponse({'secret': 'data'})
"""

from functools import wraps
import json
import base64

from django.conf import settings
from django.http import JsonResponse, HttpResponse

from ...shield import Shield


class ShieldMiddleware:
    """
    Django middleware for automatic response encryption.

    Add to MIDDLEWARE in settings.py:
        'shield.integrations.django.ShieldMiddleware'

    Configure in settings.py:
        SHIELD_PASSWORD = 'your-password'
        SHIELD_SERVICE = 'your-service'
        SHIELD_ENCRYPT_PATHS = ['/api/']  # Optional: only encrypt these paths
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.password = getattr(settings, 'SHIELD_PASSWORD', None)
        self.service = getattr(settings, 'SHIELD_SERVICE', 'django-app')
        self.encrypt_paths = getattr(settings, 'SHIELD_ENCRYPT_PATHS', None)

        if self.password:
            self.shield = Shield(self.password, self.service)
        else:
            self.shield = None

    def __call__(self, request):
        response = self.get_response(request)

        if not self.shield:
            return response

        # Check if path should be encrypted
        if self.encrypt_paths:
            should_encrypt = any(
                request.path.startswith(path)
                for path in self.encrypt_paths
            )
            if not should_encrypt:
                return response

        # Only encrypt JSON responses
        content_type = response.get('Content-Type', '')
        if 'application/json' not in content_type:
            return response

        # Check for opt-out header
        if request.headers.get('X-Shield-Bypass') == 'true':
            return response

        # Encrypt response
        try:
            encrypted = self.shield.encrypt(response.content)
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')

            return JsonResponse({
                'encrypted': True,
                'data': encrypted_b64
            })
        except Exception:
            # On encryption failure, return original response
            return response


def shield_protected(view_func=None, password=None, service=None):
    """
    Decorator to encrypt view responses.

    Usage:
        @shield_protected
        def my_view(request):
            return JsonResponse({'secret': 'data'})

        @shield_protected(password='custom-pw', service='custom-svc')
        def my_view(request):
            return JsonResponse({'secret': 'data'})
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            response = func(request, *args, **kwargs)

            pw = password or getattr(settings, 'SHIELD_PASSWORD', None)
            svc = service or getattr(settings, 'SHIELD_SERVICE', 'django-app')

            if not pw:
                return response

            shield = Shield(pw, svc)

            if isinstance(response, JsonResponse):
                encrypted = shield.encrypt(response.content)
                encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                return JsonResponse({
                    'encrypted': True,
                    'data': encrypted_b64
                })

            return response
        return wrapper

    if view_func:
        return decorator(view_func)
    return decorator


def shield_required(view_func=None, password=None, service=None):
    """
    Decorator requiring encrypted request body.

    Usage:
        @shield_required
        def my_view(request):
            # request.shield_data contains decrypted data
            return JsonResponse({'received': request.shield_data})
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            pw = password or getattr(settings, 'SHIELD_PASSWORD', None)
            svc = service or getattr(settings, 'SHIELD_SERVICE', 'django-app')

            if not pw:
                return JsonResponse(
                    {'error': 'Shield not configured'},
                    status=500
                )

            shield = Shield(pw, svc)

            try:
                body = json.loads(request.body)
                if body.get('encrypted') and body.get('data'):
                    encrypted = base64.b64decode(body['data'])
                    decrypted = shield.decrypt(encrypted)
                    request.shield_data = json.loads(decrypted)
                else:
                    return JsonResponse(
                        {'error': 'Encrypted request required'},
                        status=400
                    )
            except Exception:
                return JsonResponse(
                    {'error': 'Decryption failed'},
                    status=400
                )

            return func(request, *args, **kwargs)
        return wrapper

    if view_func:
        return decorator(view_func)
    return decorator


class EncryptedSessionMiddleware:
    """
    Middleware to encrypt Django session data.

    Add AFTER SessionMiddleware in MIDDLEWARE:
        'django.contrib.sessions.middleware.SessionMiddleware',
        'shield.integrations.django.EncryptedSessionMiddleware',
    """

    def __init__(self, get_response):
        self.get_response = get_response
        password = getattr(settings, 'SHIELD_PASSWORD', None)
        service = getattr(settings, 'SHIELD_SERVICE', 'django-session')

        if password:
            self.shield = Shield(password, service)
        else:
            self.shield = None

    def __call__(self, request):
        return self.get_response(request)


__all__ = [
    'ShieldMiddleware',
    'shield_protected',
    'shield_required',
    'EncryptedSessionMiddleware',
]
