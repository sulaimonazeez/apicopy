from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
import json
from django.db import IntegrityError, transaction
from django.contrib import messages
from .models import VirtualsAccountings, UserProfiles, Profile, Balance, Download, AccountUpgrade, GeneratePin, WalletFundings, Transaction, Post, ProcessAccount, PasswordReset

from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
#from .services import PaystackService
import logging
from .paystack_calculator import calculate_paystack_fee
from django.http import HttpResponse,HttpResponseRedirect
import random
from django_weasyprint import WeasyTemplateView
from django.views import View
from django.urls import reverse
from django.contrib.auth import update_session_auth_hash
from django.views.decorators.http import require_POST
from django.views.generic import ListView
from django.db.models import Q
from django.http import JsonResponse
from .services import PayVesselService, RegenerateAccount, RegenerateAccountBvn
import hmac
import hashlib
from django.views.decorators.csrf import csrf_exempt 
import uuid
from .purchaser import ProcessPayment
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from weasyprint import HTML
from django.template.loader import render_to_string
from .airtime import airtime_process
from .models import Payment
import requests
from django.conf import settings
from django.core.mail import send_mail
import string





def welcome(request):
  return render(request, "home.html")


@login_required
def notification(request):
  is_night = None
  try:
    nightmode = UserProfiles.objects.get(user=request.user)
    is_night = nightmode.night_mode
  except Exception:
    is_night = False
  return render(request, "notification.html", {"nightmode":is_night})






@login_required
def transaction_history(request):
  try:
    nightmode = UserProfiles.objects.get(user=request.user)
    is_night = nightmode.night_mode
  except UserProfiles.DoesNotExist:
    is_night = False
  dev = Transaction.objects.filter(user=request.user).order_by('-id')[:20]
  return render(request, 'transaction.html', {"nightmode":is_night, "dev": dev})




def register(request):
    # Check if user is already authenticated
    if request.user.is_authenticated:
        return redirect(reverse('home'))
        
    message = ""
    if request.method == "POST":
        username = request.POST.get("username")
        phone_number = request.POST.get("phone_number")
        email = request.POST.get("email")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")
        
        if User.objects.filter(email=email).exists():
          message = "Email Already Exist"
          return render(request, "create.html", {"error":message})
        # Validate form data
        if password1 and password1 == password2 and username and email:
            try:
                # Create user and save to database
                user = User.objects.create_user(username=username, email=email, password=password1)
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                # Authenticate user
                auto_log = authenticate(username=username, password=password1)
                if auto_log is not None:
                    login(request, auto_log)
                    Profile.objects.create(user=auto_log, phone_number=phone_number)
                    messages.success(request, "Account successfully created")
                    return redirect(reverse('home'))
                else:
                    context = {'error': 'Login failed. Please try again.'}
                    return render(request, 'create.html', context)

            except IntegrityError:
                context = {'error': 'Username or email already exists.'}
                return render(request, 'create.html', context)
            except Exception as e:
                context = {'error': f'An error occurred: {e}'}
                return render(request, 'create.html', context)
        else:
            context = {'error': 'Invalid form submission. Please check your details and try again.'}
            return render(request, 'create.html', context)

    return render(request, 'create.html', {"error":message})




def logged(request):
  #check if user is already authenticated
  if request.user.is_authenticated:
    return redirect("/home")
  
  #check method
  if request.method == "POST":
    try:
      username = request.POST.get("username")
      password = request.POST.get("password")
      auth = authenticate(username=username, password=password)
      if auth is not None:
        login(request, auth)
        messages.success(request, "Successful Login")
        return redirect("/home")
      else:
        messages.error(request, "incorrect Password or Username")
        return render(request, "login.html", {"error": "Invalid Crediential"})
    except Exception as e:
      print(e)
      print("Error occured while login")
      return HttpResponse("Error occured while login")
  return render(request, 'login.html')
  
 
 
 
 
 
  
logger = logging.getLogger(__name__)
@login_required
def home(request):
  pin, is_generated = False, False
  account_no, bank = "",""
  #generating account number
  try:
    transact = Transaction.objects.filter(user=request.user)[::-1][:3]
  except Exception as e:
    print("something went wrong", e)
  try:
        phone_getter = Profile.objects.get(user=request.user)
        phone = phone_getter.phone_number
        if not VirtualsAccountings.objects.filter(user=request.user).exists():
            account_number = PayVesselService.generate_virtual_account(request.user, phone)
            logger.debug(f"Account number response: {account_number}")
            details = account_number['banks'][0]
            logger.debug(f"Details extracted: {details}")
            accounts = VirtualsAccountings.objects.create(
                user=request.user,
                account_number=details["accountNumber"],
                bank_name=details["bankName"],  # Ensure this is correct
                order_ref=details["trackingReference"]
            )
            accounts.save()
        result = VirtualsAccountings.objects.get(user=request.user)
        account_no = result.account_number
        bank = result.bank_name
        is_generated = True
  except KeyError as ke:
        logger.error(f"KeyError: {ke}")
        logger.error(f"Account number response structure: {account_number}")
        print(ke)
        is_generated = False
  except Exception as e:
        logger.error(f"Exception occurred: {e}")
        is_generated = False
    
  try:
    blc, mycreate = Balance.objects.get_or_create(user=request.user)
    balance = blc
  except Balance.DoesNotExist as e:
    print(e)
  
  return render(request, "uix.html", {"balance": balance, "pin":pin, "account_number":account_no, "bank":bank,"account_generate":is_generated, "transact":transact})
  






logger = logging.getLogger(__name__)
@login_required
def generate_virtual_account(request):
    user = request.user
    try:
        account_number = PayVesselService.generate_virtual_account(user)
        return JsonResponse({'success': True, 'account_number': account_number})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)







def push_out(request):
  logout(request)
  return redirect("/accounts/login")
  
@login_required
def night_mode(request):
    try:
        # Check if the user profile exists
        user_profile = UserProfiles.objects.get(user=request.user)
        # Toggle the night_mode field
        user_profile.night_mode = not user_profile.night_mode
        user_profile.save()
        messages.success(request, "Night Mode Activated")
        return redirect("/home")
    except UserProfiles.DoesNotExist:
        try:
            # If user profile does not exist, create one
            UserProfiles.objects.create(user=request.user, night_mode=True)
            messages.success(request, "Night Mode Activated")
            return redirect("/home")
        except Exception as e:
            # Handle any exception that might occur during profile creation
            messages.error(request, "Something went wrong")
            return HttpResponse(f"An error occurred while creating the user profile: {e}")
    except Exception as e:
        # Handle any other exceptions
        messages.error(request, "Something went wrong")
        return HttpResponse(f"An error occurred: {e}")








@login_required
def purchase_data(request):
  is_night = None
  message = "Incorrect Pin please try again"
  success = "ERROR!!"
  pin = ""
  balanced = 0
  try:
    balance, blc = Balance.objects.get_or_create(user=request.user)
    balanced = balance.balance
  except Exception:
    return HttpResponse("Something went wrong")
  try:
    x, y = GeneratePin.objects.get_or_create(user=request.user)
    pin = x.pin
  except Exception:
    messages.error("User not Exists")
    return HttpResponse("Models not exist")
  try:
    nightmode = UserProfiles.objects.get(user=request.user)
    is_night = nightmode.night_mode
  except Exception:
    is_night = False
  return render(request, "data_init.html", {"nightmode":is_night, "pin":pin, "message":message, "success":success, "balanced": balanced})
  
  
@login_required
def buy_bundle(request):
    
    if request.method == "POST":
        try:
            user = request.user
            charge = request.POST.get("amount")
            phone_number = request.POST.get("phone")
            data_amount = request.POST.get("dataType")
            dataType = request.POST.get("sme")
            service = request.POST.get("network")
            

            x = Balance.objects.get(user=user)

            # Check if balance is sufficient
            if x.balance >= int(charge):
                data_process = ProcessPayment()
                with transaction.atomic():
                  # Deduct balance
                  user_data = data_process.process_data(service,dataType, data_amount)
                  print(user_data)
                  send_data = data_process.make_request(user_data, phone_number)
                  print(send_data)
                  x.balance -= int(charge)
                  x.save()

                  dmessages = f"Purchase of {data_amount} Plan for phone number {phone_number}"
                  Transaction.objects.create(user=request.user, status=send_data["status"], message=dmessages, reference=send_data["data"]["reference"], network=send_data["data"]["network"], data_plan=send_data["data"]["dataPlan"], data_type=send_data["data"]["dataType"], amount=charge, status_code=True, balance=x)
                  messages.success(request, "Successful Purchase")
                  x = Transaction.objects.filter(user=user)[::-1][0]
                  return redirect(f'/myreciept/{x.id}')
            else:
                messages.error(request, "Insufficient balance")
                return HttpResponse('Insufficient balance')

        except Balance.DoesNotExist:
            return HttpResponse('Balance record not found')

        except Exception as e:
            return HttpResponse(f"Error occurred: {str(e)}")

    return redirect("/home")
    
    
    
    
    
    
    
    
"""
class MyReciept(View):
    def get(self, request, id, *args, **kwargs):
        x = get_object_or_404(Development, id=id)
        old_balance = x.amount + x.balance.balance
        if request.GET.get('download'):
            # Handle the PDF download
            response = WeasyTemplateResponse(
                request=request,
                template='invoice.html',
                context={
                    'date': '2024-07-22',
                    'customer_name': 'John Doe',
                    'amount': '$100'
                },
                filename='invoice.pdf'
            )
            response.render()
            pdf = response.rendered_content

            response = HttpResponse(pdf, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="invoice.pdf"'
            return response

        # Render the initial content
        return render(request, 'reciept.html',{"reciept":x, "old":old_balance})

"""

@login_required
def myreciept(request, id):
  x = get_object_or_404(Transaction, id=id)
  old_balance = x.amount + x.balance.balance
  return render(request, "reciept.html", {"reciept":x, "old":old_balance})
  




def generate_pdf(request, id):
    transaction = get_object_or_404(Transaction, id=id)
    old_balance = transaction.amount + transaction.balance.balance
    
    try:
        downloaded, created = Download.objects.get_or_create(user=request.user)
        if not created:
            downloaded.downloaded += 1
            downloaded.save()
        pdf_filename = f"reciept_pystar{downloaded.downloaded}.pdf"
    except Exception as e:
        print(f"Error: {e}")
        pdf_filename = "reciept_pystar1.pdf"
    
    html_string = render_to_string('invoice.html', {
        'reciept': transaction,
        'old': old_balance,
    })
    html = HTML(string=html_string)
    pdf = html.write_pdf()

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'filename="{pdf_filename}"'
    
    return response



    
@login_required
def profile(request):
  success = ""
  #message to display in the templates
  message = ""
  #exist
  same_password = False
  #currentmatch
  old_password = False
  #to handle both sucessful and check new password with retype password 
  ischange = False
  is_password_match = False
  try:
    check = request.GET.get("ischange")
    if check == "true":
      ischange = True
      message = "Password successfully change"
      success = "Successful"
    elif check == "false":
      is_password_match  = True
      message = "New Password is not match with confirm password"
      success = "ERROR!!"
    else:
      ischange = False
  except Exception:
    print("ischange not available")
    
  try:
    check = request.GET.get("currentmatch")
    if check == "false":
      old_password = True
      message = "Password not match with the old password"
      success = "ERROR!!"
    else:
      old_password  = False
  except Exception:
    print("ischange not available")
    
  try:
    check = request.GET.get("exist")
    if check == "true":
      same_password = True
      message = "Cannot use same password"
      success = "ERROR!!"
    else:
      same_password  = False
  except Exception:
    print("ischange not available")
  try:
    profiles, created = Profile.objects.get_or_create(user=request.user)
  except Profile.DoesNotExist:
    return HttpResponse("Models not exists")
  except Exception as e:
    return HttpResponse(f"Error occurred: {e}")
    
  is_night, create_night = UserProfiles.objects.get_or_create(user=request.user)
  return render(request, "profile.html", {"profile":profiles, "message": message, "ischange": ischange, "old_password": old_password, "same_password": same_password, "is_match": is_password_match, "success":success, "nightmode":is_night})
  
  
  
  
  
  
  
  
  
@login_required
@require_POST
def change_password(request):
    current_password = request.POST.get('current_password')
    new_password = request.POST.get('new_password')
    confirm_password = request.POST.get('confirm_password')
    user = request.user
    
    if (new_password != confirm_password) and len(new_password) >= 2:
      messages.error(request, "Password not match")
      return redirect("/profile?ischange=false")
    
    if user.check_password(new_password):
      messages.error("Cannot use same password")
      return redirect("/profile?exist=true")
    # Check the current password
    if not user.check_password(current_password):
        messages.error(request, "Current password is incorrect.")
        return redirect('/profile?currentmatch=false')  # Redirect to the password change page
    
    # Set and save the new password
    user.set_password(new_password)
    user.save()
    
    # Update the session to prevent logout
    update_session_auth_hash(request, user)
    
    messages.success(request, "Password changed successfully.")
    return redirect('/profile?ischange=true')  # Redirect to a success page


def change_pin(request):
  list(messages.get_messages(request))
  if request.method == "POST":
    try:
      mypin, crt = GeneratePin.objects.get_or_create(user=request.user)
      new_pin = request.POST.get("newpin")
      oldpin = request.POST.get("oldpin")
      confirm_pin = request.POST.get("retypepin")
      if new_pin != confirm_pin:
        messages.error(request, "Password not match")
        return redirect("/profile")
        
      if oldpin != mypin.pin:
        messages.error(request, "Old Password Not Match")
        return redirect("/profile")
      if new_pin == mypin.pin:
        messages.error(request, "Cannot use same passworď")
        return redirect("/profile")
        
      mypin.pin = new_pin
      mypin.save()
      messages.success(request, "Pin successfully changed")
      return redirect(reverse("profile"))
    except Exception as e:
      print("something went wrong", e)
      return HttpResponse("Something Went Wrong")
  else:
    return redirect("/profile")
    


class SearchResultsView(ListView):
  model = Transaction
  template_name = 'transaction.html'
  context_object_name = 'dev'

  def get_queryset(self):
    query = self.request.GET.get('q')
    if query:
      result = Transaction.objects.filter(Q(message__icontains=query)|Q(data_plan__icontains=query)|Q(amount__icontains=query), user=self.request.user)
      return result.order_by('-id')
    return Transaction.objects.none()
    
  def get_context_data(self, **kwargs):
    is_night = None
    try:
      nightmode = UserProfiles.objects.get(user=self.request.user)
      is_night = nightmode.night_mode
    except Exception:
      is_night = False
      print('Something went wrong')
    context = super().get_context_data(**kwargs)
    # Add your additional data here
    context['nightmode'] = is_night
    # For example, you might want to pass a count of results
    context['total_results'] = self.get_queryset().count()
    return context
    
    
@require_POST
@csrf_exempt
@transaction.atomic
def payvessel_payment_done(request):
    payload = request.body
    payvessel_signature = request.META.get('HTTP_PAYVESSEL_HTTP_SIGNATURE')
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
    
    if ip_address:
        ip_address = ip_address.split(',')[0].strip()  # Take the first IP in the list
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    
    secret = bytes("PVSECRET-", 'utf-8')
    hashkey = hmac.new(secret, request.body, hashlib.sha512).hexdigest()
    ipAddress = ["3.255.23.38", "162.246.254.36"]

    # Security check (uncomment when in production)
    #if payvessel_signature == hashkey and ip_address in ipAddress:
    if True:
        try:
            data = json.loads(payload)
            amount = float(data['order']["amount"])
            settlementAmount = float(data['order']["settlement_amount"])
            fee = float(data['order']["fee"])
            reference = data['transaction']["reference"]
            description = data['order']["description"]
            settlementAmount = settlementAmount 
            fees = fee
            users = data['customer']['email']
            settle_amount = settlementAmount

            # Check if reference already exists
            if not WalletFundings.objects.filter(transaction_reference=reference).exists():
                if amount > 3000:
                    fees += 50
                    settle_amount -= 50
                else:
                    fees += 25
                    settle_amount -= 25
                
                #user_obj = User.objects.get(email=f'{users}')
                WalletFundings.objects.create(user=users, fund_amount=amount, settle_amount=settle_amount, fees=fees, transaction_reference=reference, desciption=description, status=True, header="Account Fund")
                return JsonResponse({"message": "success"}, status=200) 
            else:
                return JsonResponse({"message": "transaction already exists"}, status=200) 

        except Exception as e:
            return JsonResponse({"message": f"Internal Server error: {e}"}, status=500)
    else:
        return JsonResponse({"message": "Permission denied, invalid hash or IP address"}, status=400)
  



class DataApi(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            charge = int(request.data.get("amount"))
            phone_number = request.data.get("phone")
            data_amount = request.data.get("dataType")
            dataType = request.data.get("sme")
            service = request.data.get("network")

            if not phone_number or not data_amount or not dataType or not service:
                return Response({"status": "failed", "message": "Invalid data provided"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Manually handle the transaction and make sure select_for_update is inside atomic block
                with transaction.atomic():
                    # Lock the balance row to prevent race conditions
                    balance = Balance.objects.select_for_update().get(user=request.user)

                    if balance.balance < charge:
                        return Response({"status": "failed", "message": "Insufficient funds"}, status=status.HTTP_403_FORBIDDEN)

                    # Call your payment processing methods
                    data_process = ProcessPayment()
                    user_data = data_process.process_data(service, dataType, data_amount)
                    send_data = data_process.make_request(user_data, phone_number)

                    # Deduct balance
                    balance.balance -= charge
                    balance.save()

                    dmessages = f"Purchase of {data_amount} Plan for phone number {phone_number}"
                    Transaction.objects.create(
                        user=request.user,
                        status=send_data["status"],
                        message=dmessages,
                        reference=send_data["data"]["reference"],
                        network=send_data["data"]["network"],
                        data_plan=send_data["data"]["dataPlan"],
                        data_type=send_data["data"]["dataType"],
                        amount=charge,
                        status_code=True,
                        balance=balance
                    )

                    messages.success(request, "Successful Purchase")

                    content = {
                        "status": send_data["status"],
                        "message": dmessages,
                        "reference": send_data["data"]["reference"],
                        "network": send_data["data"]["network"],
                        "dataPlan": send_data["data"]["dataPlan"],
                        "dataType": send_data["data"]["dataType"],
                        "amount": charge
                    }
                    return Response(content, status=status.HTTP_200_OK)

            except IntegrityError:
                # If something goes wrong, the transaction will roll back
                return Response({"status": "failed", "message": "Transaction failed, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({"status": "failed", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            

def airtime_init(request):
  balance = 0
  try:
    balance, blc = Balance.objects.get_or_create(user=request.user)
    balanced = balance.balance
  except Exception:
    return HttpResponse("Something went wrong")
  try:
    x, y = GeneratePin.objects.get_or_create(user=request.user)
    pin = x.pin
  except Exception:
    messages.error("User not Exists")
    return HttpResponse("Models not exist") 
  return render(request, 'airtime.html', {"pin":pin,"balanced": balanced})
 
@login_required 
@require_POST
def airtime_purchase(request):
  try:
    network = request.POST.get("network")
    phone_number = request.POST.get("phone")
    amount = int(request.POST.get("amount"))
    balance = Balance.objects.get(user=request.user)
    if balance.balance >= amount:
      send_data = airtime_process(phone_number, network, amount)
      print(send_data)
      with transaction.atomic():
        balance.balance -= amount
        balance.save()
        dmessage = f"Airtime Successful Purchase for {phone_number}"
        Transaction.objects.create(user=request.user, status=send_data["status"], message=dmessage, reference=send_data["data"]["reference"], network=send_data["data"]["network"], data_plan=send_data["data"]["network"], data_type=send_data["data"]['amountCharged'], amount=amount, status_code=True, balance=balance)
      messages.success(request, "Successful Purchase")
      x = Transaction.objects.filter(user=request.user)[::-1][0]
      return redirect(f'/myreciept/{x.id}')
    else:
      messages.error(request, "Insufficient balance")
      return HttpResponse('Insufficient balance')
      
  except Balance.DoesNotExist:
    return HttpResponse('Balance record not found')
    
  except Exception as e:
    return HttpResponse(f"Error occurred: {str(e)}")
    
    
    
class AirtimeApi(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            network = request.data.get("network")
            phone_number = request.data.get("phone")
            amount = int(request.data.get("amount"))
            #balance = Balance.objects.get(user=request.user)

            if not phone_number or not network or amount:
                return Response({"status": "failed", "message": "Invalid data provided"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Manually handle the transaction and make sure select_for_update is inside atomic block
                with transaction.atomic():
                    # Lock the balance row to prevent race conditions
                    balance = Balance.objects.select_for_update().get(user=request.user)

                    if balance.balance < amount:
                        return Response({"status": "failed", "message": "Insufficient funds"}, status=status.HTTP_403_FORBIDDEN)

                    # Call your payment processing methods
                    send_data = airtime_process(phone_number, network, amount)

                    # Deduct balance
                    balance.balance -= int(amount)
                    balance.save()

                    dmessage = f"Airtime Successful Purchase for {phone_number}"
                    Transaction.objects.create(user=request.user, status=send_data["status"], message=dmessage, reference=send_data["data"]["reference"], network=send_data["data"]["network"], data_plan=send_data["data"]["network"], data_type=send_data["data"]['amountCharged'], amount=amount, status_code=True, balance=balance)

                    messages.success(request, "Successful Purchase")

                    content = {
                        "status": send_data["status"],
                        "message": dmessage,
                        "reference": send_data["data"]["reference"],
                        "network": send_data["data"]["network"],
                        "dataPlan": send_data["data"]["network"],
                        "dataType": send_data["data"]["amountCharged"],
                        "amount": amount
                    }
                    return Response(content, status=status.HTTP_200_OK)

            except IntegrityError:
                # If something goes wrong, the transaction will roll back
                return Response({"status": "failed", "message": "Transaction failed, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({"status": "failed", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  
  


def payment_callback(request):
    reference = request.GET.get('reference')

    # Verify the transaction
    headers = {
        'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
    }

    response = requests.get(f'https://api.paystack.co/transaction/verify/{reference}', headers=headers)
    response_data = response.json()

    if response_data['status']:
        payment = Payment.objects.get(reference=reference)
        payment.status = 'success'
        payment.save()

        # Perform additional actions here, like providing the user with VTU services
        return redirect("/home")
    else:
        return JsonResponse({'status': 'Payment verification failed!'})
        
        
        


    
    
    
def blog_post(request):
  #blogs details
  blogs = Post.objects.all()
  return render(request, "blogs.html", {"content":blogs})
  

logger = logging.getLogger(__name__)
@login_required
def regenerate_virtual_account(request):
  if request.method == "POST":
    try:
      nin = request.POST.get("nin")
      logger.debug(f"Getting National Identification Number {nin}")
      if ProcessAccount.objects.filter(user=request.user).exists():
        profile = ProcessAccount.objects.get(user=request.user)
        profile.nin = nin
        profile.save()
      else:
        processing = ProcessAccount.objects.create(user=request.user, nin=nin)
        processing.save()
      
      phone_getter = Profile.objects.get(user=request.user)
      phone = phone_getter.phone_number
      account_number = RegenerateAccount.generate_virtual_account(request.user, phone, nin)
      logger.debug(f"Account number response: {account_number}")

      details = account_number['banks'][0]
      logger.debug(f"Details extracted: {details}")
      print(details)
      print(account_number)
      if not VirtualsAccountings.objects.filter(user=request.user).exists():
          accounts = VirtualsAccountings.objects.create(
              user=request.user,
              account_number=details["accountNumber"],
              bank_name=details["bankName"],  # Ensure this is correct
              order_ref=details["trackingReference"]
            )
          accounts.save()
      
      return HttpResponse("Account Created successfully")
    except Exception as e:
      logger.error(f"Something Went wrong while generating account number {e}")
      print("Soemthing went unable")
  return render(request, "process.html")
  
  



logger = logging.getLogger(__name__)
@login_required
def regenerate_virtual_account_bvn(request):
  if request.method == "POST":
    try:
      nin = request.POST.get("nin")
      logger.debug(f"Getting National Identification Number {nin}")
      if ProcessAccount.objects.filter(user=request.user).exists():
        profile = ProcessAccount.objects.get(user=request.user)
        profile.nin = nin
        profile.save()
      else:
        processing = ProcessAccount.objects.create(user=request.user, nin=nin)
        processing.save()
      
      phone_getter = Profile.objects.get(user=request.user)
      phone = phone_getter.phone_number
      account_number = RegenerateAccountBvn.generate_virtual_account(request.user, phone, nin)
      logger.debug(f"Account number response: {account_number}")

      details = account_number['banks'][0]
      logger.debug(f"Details extracted: {details}")
      print(details)
      print(account_number)
      if not VirtualsAccountings.objects.filter(user=request.user).exists():
          accounts = VirtualsAccountings.objects.create(
              user=request.user,
              account_number=details["accountNumber"],
              bank_name=details["bankName"],  # Ensure this is correct
              order_ref=details["trackingReference"]
            )
          accounts.save()
      
      return HttpResponse("Account Created successfully")
    except Exception as e:
      logger.error(f"Something Went wrong while generating account number {e}")
      print("Soemthing went unable")
  return render(request, "bvn.html")
  
  







        

@login_required
def initiate_payment(request):
    if request.method == "POST":
        email = request.POST.get('email')
        amount = int(request.POST.get('amount')) * 100  # Convert to kobo

        headers = {
            'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
            'Content-Type': 'application/json',
        }

        data = {
            'email': email,
            'amount': amount,
            'callback_url': 'http://paystar.com.ng/paystack/payment/done/',
        }

        response = requests.post('https://api.paystack.co/transaction/initialize', headers=headers, json=data)
        response_data = response.json()
        process_fees = 10
        paystack_fees = calculate_paystack_fee(amount)
        amt = (amount - paystack_fees) / 100 - process_fees
        if response_data['status']:
            # Store payment in your database
            payment = Payment.objects.create(
                user=request.user,
                reference=response_data['data']['reference'],
                amount=amt,  # Convert back to naira
                email=email
            )
            payment.save()
            # Redirect to Paystack payment page
            return redirect(response_data['data']['authorization_url'])
        else:
            return render(request, 'payment_failed.html', {'message': response_data['message']})
    #get user gmail address and passed it to my templates        
    user = request.user.email
    return render(request, 'payment.html',{"user":user})




def forget_password(request):
  if request.method == "POST":
    try:
      
      email = request.POST.get('email')
      digits = string.digits
      otp = ''.join(random.choice(digits) for _ in range(6))
      if email is not None:
        if User.objects.filter(email=email).exists():
          subject = "Password Reset OTP"
          message = f"Your One time OTP is {otp} please use the code within 5 minutes or request another one thanks you. PAYSTAR"
          recipient_list = [f'{email}']
          try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list)
            users = User.objects.get(email=email)
            PasswordReset.objects.create(user=users, random_code=otp, staus=True)
            return redirect("/confirm/otp")
          except Exception as e:
            return HttpResponse(f'Failed to send email: {str(e)}')
    except Exception as e:
      print("Something went wrong unable to generate otp",e)
      return HttpResponse("Error Unabe to Generate form...")
  return render(request, "forget.html")


def confirm_otp(request):
  message = ""
  if request.method == "POST":
    try:
      otp = request.POST.get("otp")
      if PasswordReset.objects.filter(random_code=otp).exists():
        user = PasswordReset.objects.get(random_code=otp)
        user.is_verify = True
        user.save()
        return redirect("/verify")
      else:
        print("Invalid Otp")
        message = "Invalid OTP please try again"
    except Exception as e:
      print("Soemthing went wrong... ", e)
      message = "Something went wrong unable to verify otp"
  return render(request, "confirm.html", {"error":message})





def verify(request):
  message = ""
  if request.method == "POST":
    email = request.POST.get("email")
    password = request.POST.get("password")
    password2 = request.POST.get("password1")
    
    if (password and password2 and password2 == password and email):
      if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        verifiyer = PasswordReset.objects.get(user=user)
        if user.check_password(password):
          message = "Cannot Use Same Password"
          return render(request, "verify.html", {"error":message})
        if verifiyer.is_verify:
          user.set_password(password)
          user.save()
          verifiyer.delete()
          return redirect("/accounts/login")
        else:
          return redirect("/password/reset")
      else:
        message = "Invalid Email Address please check your email and try again."
        return render(request, "verify.html", {"error":message})
    else:
      message = "Password doesn't match or Email Address please check your input field.."
      return render(request, "verify.html", {"error":message})
          
  return render(request, "verify.html")

"""def send_email_from_cpanel(request):
    subject = 'Welcome to Paystar'
    message = 'Thank you for signing up at Paystar!'
    recipient_list = ['olaniyisulaimon221@gmail.com']  # Change this to the recipient's email
    
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list)
        return HttpResponse('Email sent successfully!')
    except Exception as e:
        return HttpResponse(f'Failed to send email: {str(e)}')
  """