from __future__ import annotations

from django.utils.deprecation import MiddlewareMixin

from .context import AuditContext, clear_audit_context, set_audit_context
from apps.core.net import get_client_ip


class AuditContextMiddleware(MiddlewareMixin):
    def process_request(self, request):
        user_id = getattr(getattr(request, "user", None), "id", None)
        ip = get_client_ip(request).ip
        set_audit_context(AuditContext(user_id=user_id, ip=ip))

    def process_response(self, request, response):
        clear_audit_context()
        return response

    def process_exception(self, request, exception):
        clear_audit_context()
        return None
