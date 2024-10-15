from django.contrib import admin
from .models import Profile, Balance, VirtualsAccountings,UserProfiles,Download, GeneratePin, AccountUpgrade, Transaction


#admin.site.register(Profile)
admin.site.register(Balance)
admin.site.register(VirtualsAccountings)
admin.site.register(UserProfiles)
admin.site.register(Transaction)
admin.site.register(Download)
admin.site.register(GeneratePin)
admin.site.register(AccountUpgrade)