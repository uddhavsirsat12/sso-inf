from django.contrib import admin
from django.urls import path, include
from .views import GroupList
from.import views
from .views import MyUserView
from django.contrib.auth import views as auth_views
from django.urls import path
from .views import UserDetail
from oauth2_provider.views import (
    AuthorizationView,
    TokenView,
    RevokeTokenView,
)
urlpatterns = [
    path('my-login/',views.login_view,name='my-login'),
    path('register',views.register_1,name='register'),
    path('accounts/login/', auth_views.LoginView.as_view(), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('logout',views.logout_1,name='logout'),
    # path('home',views.home,name= 'home'),
    path('users/', UserDetail.as_view(), name='user-detail'),
    path('groups/', GroupList.as_view()),
    path('authorize/', AuthorizationView.as_view(), name='authorize'),
    path('token/', TokenView.as_view(), name='token'),
    path('revoke_token/', RevokeTokenView.as_view(), name='revoke-token'),
    path('user/', MyUserView.as_view(), name='user'),
    path('as/', views.access, name='access'),
]

# from oauth2_provider.urls