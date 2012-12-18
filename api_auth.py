from django.conf.urls import url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User

from tastypie.authentication import Authentication
from tastypie.authorization import Authorization

from tastypie.http import HttpUnauthorized, HttpForbidden
from tastypie.resources import ModelResource


class ApiTokenAuthentication( Authentication ):
    def is_authenticated( self, request, **kwargs ):
        return True

    def get_identifier( self, request ):
        return request.user.username


class ApiTokenAuthorization( Authorization ):
    def is_authorized( self, request, object=None ):
        return True

    def apply_limits( self, request, object_list ):
        return None


class UserResource( ModelResource ):
    class Meta:
        queryset = User.objects.all()
        fields = [ 'username', 'email' ]
        allowed_methods = [ 'get', 'post' ]
        resource_name = 'user'

    def override_urls( self ):
        return [
            url( r'^(?P<resource_name>%s)/login/$' %
                    ( self._meta.resource_name ),
                    self.wrap_view( 'login' ), name='api_login' ),
            url( r'^(?P<resource_name>%s)/logout/$' %
                    ( self._meta.resource_name ),
                    self.wrap_view( 'logout' ), name='api_logout' ) ]

    def login( self, request, **kwargs ):
        self.method_check( request, allowed=[ 'get' ] )

        data = request.GET

        username = data.get( 'username', '' )
        password = data.get( 'password', '' )
        token    = data.get( 'token', '' )

        user = authenticate(username=username, password=password, token=token)
        if user:
            if user.is_active:
                login(request, user)
                return self.create_response(request, {
                    'success': True
                })
            else:
                return self.create_response(request, {
                    'success': False,
                    'reason': 'disabled',
                    }, HttpForbidden)
        else:
            return self.create_response(request, {
                'success': False,
                'reason': 'incorrect',
                }, HttpUnauthorized)

    def logout(self, request, **kwargs):
        self.method_check(request, allowed=['get'])
        if request.user and request.user.is_authenticated():
            logout(request)
            return self.create_response(request, { 'success': True })
        else:
            return self.create_response(request, { 'success': False },
                                        HttpUnauthorized)
