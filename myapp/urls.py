from django.urls import path
from . import views
from django.contrib.sitemaps.views import sitemap
from .sitemap import StaticSitemap

sitemaps = {
    'static': StaticSitemap,
}

urlpatterns = [
  path("", views.welcome, name="welcome"),
  path("accounts/login/", views.logged, name="login"),
  path("accounts/create/", views.register, name="register"),
  path("home", views.home, name="home"),
  path("generate_account", views.generate_virtual_account),
  path("logout", views.push_out),
  path("history", views.transaction_history),
  path("notification", views.notification),
  path("nightmode", views.night_mode),
  path("databundle", views.purchase_data), 
  path("purchase", views.buy_bundle),
  path("myreciept/<int:id>/", views.myreciept),
  path("invoice/<int:id>/", views.generate_pdf),
  path("profile", views.profile, name="profile"),
  path("change/password/", views.change_password),
  path("change/pin/", views.change_pin),
  path("finder/", views.SearchResultsView.as_view()),
  path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='sitemap'),
  path("payment/done/", views.payvessel_payment_done, name="payvessel_payment_done"),
  path('api/', views.DataApi.as_view()),
  path("airtime/", views.airtime_init),
  path("airtime/purchase", views.airtime_purchase),
  path("airtime/api", views.AirtimeApi.as_view()),
  path('payment/initiate/', views.initiate_payment, name='initiate_payment'),
  path('paystack/payment/done/', views.payment_callback, name='payment_callback'),
  path("verification/nin", views.regenerate_virtual_account, name="nin"),
  path("verification/bvn", views.regenerate_virtual_account_bvn, name="bvn"),
  #path("mail", views.send_email_from_cpanel, name="mail"),
  path("password/reset", views.forget_password, name="reset_password"),
  path("confirm/otp", views.confirm_otp, name='confirm_otp'),
  path("verify", views.verify, name="verify"),
]

