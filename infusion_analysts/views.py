import requests
from oauth2_provider.views import TokenView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from oauth2_provider.views.generic import ProtectedResourceView, ScopedProtectedResourceView
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from oauth2_provider.views import AuthorizationView
from rest_framework.views import APIView
from oauth2_provider.models import RefreshToken
from django.urls import reverse
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth.models import User, Group
from rest_framework import generics, permissions
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, TokenHasScope
from .serializers import UserSerializer, GroupSerializer
from django.contrib.auth import login, logout
from urllib.parse import urlencode, unquote

# Create your views here.

def register_1(request):
    if request.method == "POST":
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        re_password = request.POST['re_password']
        if password == re_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exist')
                return render(request, 'register.html')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'email already exist')
                return render(request, 'register.html')
            else:
                user = User.objects.create_user(
                    first_name=first_name, last_name=last_name, username=username, email=email, password=password)
                user.save()
                return redirect('login')
        else:
            messages.error(request, 'password does not match')
            return render(request, 'register.html')
    else:
        return render(request, 'register.html')


def logout_1(request):
    logout(request)
    return redirect('register')

def home_1(request):
    return render(request, 'base.html')


def generate_tokens(request):
    url = settings.OAUTH_TOKEN_URL
    client_id = settings.OAUTH_CLIENT_ID
    client_secret = settings.OAUTH_CLIENT_SECRET
    grant_type = 'client_credentials'
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': grant_type,
    }
    response = requests.post(url, data=data)
    print(response)
    access_token = response.json()['access_token']
    refresh_token_url = settings.OAUTH_REFRESH_TOKEN_URL
    refresh_data = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': response.json()['refresh_token'],
    }
    refresh_response = requests.post(refresh_token_url, data=refresh_data)
    refresh_token = refresh_response.json()['refresh_token']
    return JsonResponse({'access_token': access_token, 'refresh_token': refresh_token})


class TokenRefresh(APIView):
    """
    list all token or create token
    """

    def post(self, request, format=None):
        data = request.data
        user_id = data['user_id']
        client_id = data['client_id']
        client_secret = data['client_secret']
        token_obj = RefreshToken.objects.filter(user=user_id).order_by('id')
        refresh_token = ''
        if token_obj:
            token_obj = token_obj[0]
            refresh_token = token_obj.token
        url = 'http://' + request.get_host() + '/o/token'
        print(url)
        data_dict = {'grant_type': 'refresh_token', 'client_id': client_id,
                     'client_secret': client_secret, 'refresh_token': refresh_token}
        response = requests.post(url, data=data_dict)
        data = response.json()
        # return Response(data,status=status.HTTP_201_CREATED)


def login_view(request):
    previous_url = request.META.get('HTTP_REFERER')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            # Authenticate user and log them in
            user = form.get_user()
            login(request, user)
            print('User logged in')
                # return redirect('authorize')
            return redirect(unquote(previous_url.split("=")[-1]))
        else:
            print('Invalid login')
            print(request.POST.get('debug'))
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})


class UserList(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserDetail(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]
    serializer_class = UserSerializer

    def get_object(self):
        # Retrieve the user associated with the access token
        user = self.request.user
        # Return the user object
        return user


class GroupList(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = Group.objects.all()
    serializer_class = GroupSerializer



class CustomLoginView(LoginView):
    template_name = 'login.html'


class AuthorizeView(ScopedProtectedResourceView):
    required_scopes = ['read']

    def get(self, request, *args, **kwargs):
        client_id = request.GET.get('client_id', '')
        client = Client.objects.filter(client_id=client_id).first()
        if not client:
            return redirect('login')
        context = {'client': client}
        return render(request, 'authorize.html', context)

    def post(self, request, *args, **kwargs):
        if request.POST.get('allow'):
            # User granted access, redirect to callback URL with authorization code.
            code = 'some-authorization-code'
            redirect_uri = request.GET.get('redirect_uri', '')
            callback_url = redirect_uri + '?code=' + code
            return redirect(callback_url)
        else:
            # User denied access, redirect to callback URL with error message.
            error = 'access_denied'
            redirect_uri = request.GET.get('redirect_uri', '')
            callback_url = redirect_uri + '?error=' + error
            return redirect(callback_url)



class APIView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return self.render_json_response({'foo': 'bar'})

    def post(self, request, *args, **kwargs):
        return self.render_json_response({'foo': 'baz'})

@login_required
def create_client(request):
    if request.method == 'POST':
        name = request.POST.get('name', '')
        redirect_uri = request.POST.get('redirect_uri', '')
        client = Client.objects.create(
            user=request.user, name=name, redirect_uris=redirect_uri)
        return redirect(reverse('authorize') + '?client_id=' + client.client_id)
    return render(request, 'create_client.html')


class MyAuthorizationView(AuthorizationView):
    template_name = 'oauth/authorize.html'


class MyTokenView(TokenView):
    pass


class MyUserView(ProtectedResourceView):
    pass

def access(request):
    base_url = 'http://localhost:7000/o/authorize/'

    # users = User.objects.filter(id=2)
    # data = [{'username': user.username, 'email': user.email} for user in users]

    # return JsonResponse({'data': data})

    params = {
        'client_id': 'WCIMr0eQkDjqHbEjQ63gHzoQltDXl1ObM7iuVCPq',
        'redirect_uri': 'http://localhost:8000/home',
        'scope': 'read',
        'connection': 'connection',
        'response_type': 'token',
        
    }

    url = base_url + '?' + urlencode(params)
    # print(url)
    # response = requests.get(url, params=params)
    # data = response
    # print(data)
    # user_info = {
    #     'username': request.user.username,
    #     'email': request.user.email,

    # }
    # return render(request, 'access.html', {'url': url,'user_info': user_info})

    return redirect(url)



    
# knivDb2QHwnS2J1ADg2m7ht9s1oApjPfZL6oebAsa1ELxTKaRFwld7mFd0RVWNQLdXZuvYXPwA2Lj8YKHTYV9vS0nvOt1QIeih398tG5gr9ckfykPuT4DQv97TIXsHsX


