from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponseRedirect 

def home(request):
    return HttpResponseRedirect('/api/roles/') 

urlpatterns = [
    path('', home), 
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),  # Include the app's urls
    path('api/', include('accounts.urls')), 
]
