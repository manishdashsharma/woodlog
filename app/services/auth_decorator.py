import jwt
from functools import wraps
from django.http import JsonResponse
from config.dbconfig import database
from config.config import auth_jwt_config

def login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(view, request, *args, **kwargs):
        token = request.COOKIES.get('access_token') or request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return JsonResponse({
                "success": False,
                "message": "Please login to access the resource"
            }, status=401)

        try:
            decoded_jwt_payload = jwt.decode(token, auth_jwt_config["JWT_SECRET_KEY"], algorithms=[auth_jwt_config["JWT_ALGORITHM"]])
            print(decoded_jwt_payload)
            user = database.child("user").child(decoded_jwt_payload["username"]).get().val()
            if not user:
                return JsonResponse({
                    "success": False,
                    "message": "User not found"
                }, status=401)
            request.user = user
            return view_func(view, request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({
                "success": False,
                "message": "Token has expired"
            }, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({
                "success": False,
                "message": "Invalid token"
            }, status=401)

    return _wrapped_view

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(view, request, *args, **kwargs):
        if not hasattr(request, 'user'):
            return JsonResponse({
                "success": False,
                "message": "User not authenticated"
            }, status=401)

        user = request.user
        if user.get('role') != 'admin':
            return JsonResponse({
                "success": False,
                "message": "Admin privileges required"
            }, status=403)

        return view_func(view, request, *args, **kwargs)

    return _wrapped_view