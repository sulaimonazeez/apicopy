from django.contrib.auth.models import User
from django.db import models
from django.utils.text import slugify
import itertools


class Profile(models.Model):
  user = models.OneToOneField(User, on_delete=models.CASCADE)
  phone_number = models.CharField(max_length=15, unique=True,null=True, blank=True)
  nin = models.CharField(max_length=12,unique=True, null=True,blank=True)

class Balance(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
  def __str__(self):
    return f"{self.user.username} - {self.balance}"

class VirtualsAccountings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=50)
    bank_name = models.CharField(max_length=50)
    order_ref = models.CharField(max_length=100)
    def __str__(self):
        return f"{self.user.username} - {self.account_number}"


class UserProfiles(models.Model):
  user = models.OneToOneField(User, on_delete=models.CASCADE)
  night_mode = models.BooleanField(default=False)
  


class WalletFundings(models.Model):
  user = models.CharField(max_length=500, null=False)
  fund_amount = models.DecimalField(max_digits=10, decimal_places=2)
  settle_amount = models.DecimalField(max_digits=10, decimal_places=2)
  header = models.CharField(max_length=255)
  transaction_reference = models.CharField(max_length=255, unique=True)
  fees = models.DecimalField(max_digits=10, decimal_places=2)
  desciption = models.TextField()
  status = models.BooleanField(default=False)
  date = models.DateField(auto_now_add=True)
  
  def __str__(self):
    return f"{self.user}"
  
"""class Development(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  balance = models.ForeignKey(Balance, on_delete=models.CASCADE)
  charge = models.DecimalField(max_digits=10, decimal_places=2)
  service = models.CharField(max_length=255)
  
  amount = models.DecimalField(max_digits=10, decimal_places=2)
  phone = models.CharField(max_length=255)
  data_amount = models.CharField(max_length=255)
  transaction_id = models.CharField(max_length=2000)
  date = models.DateField(auto_now_add=True)
  status = models.BooleanField(default=False)
  def __str__(self):
    return self.user.username"""
  

class Download(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  downloaded = models.IntegerField()
  
  def __str__(self):
    return self.user.username
    
class GeneratePin(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  pin = models.CharField(max_length=255, default="1111")
  
  def __str__(self):
    return self.user.username
    
class AccountUpgrade(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  upgrade = models.BooleanField(default=False)
  
  def __str__(self):
    return self.user.username

class Transaction(models.Model):
    STATUS_CHOICES = [
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    NETWORK_CHOICES = [
        ('airtel', 'Airtel'),
        ('mtn', 'MTN'),
        ('glo', 'Glo'),
        ('9mobile', '9Mobile'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    message = models.CharField(max_length=255)
    reference = models.CharField(max_length=50, unique=True)
    network = models.CharField(max_length=10, choices=NETWORK_CHOICES)
    data_plan = models.CharField(max_length=50)
    data_type = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status_code = models.BooleanField(default=False)
    balance = models.ForeignKey(Balance, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True)
    def __str__(self):
        return f"{self.network} - {self.data_plan} ({self.status})"
        
        
        


class Post(models.Model):
    title = models.CharField(max_length=200)
    sub_title1 = models.CharField(max_length=200, null=True, blank=True)
    sub_title2 = models.CharField(max_length=200, null=True, blank=True)
    sub_title3 = models.CharField(max_length=200, null=True, blank=True)
    sub_title4 = models.CharField(max_length=200, null=True, blank=True)
    sub_title5 = models.CharField(max_length=200, null=True, blank=True)
    
    slug = models.SlugField(max_length=200, unique=True, blank=True)
    content = models.TextField()
    sub_content1 = models.TextField(null=True, blank=True)
    sub_content2 = models.TextField(null=True, blank=True)
    sub_content3 = models.TextField(null=True, blank=True)
    sub_content4 = models.TextField(null=True, blank=True)
    sub_content5 = models.TextField(null=True, blank=True)
    meta_description = models.CharField(max_length=160, blank=True)  # New field for meta description
    images = models.ImageField(upload_to="static")
    pre_image = models.ImageField(upload_to="static")
    publish_date = models.DateField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            # Generate the initial slug
            self.slug = slugify(self.title)
            # Ensure the slug is unique
            for x in itertools.count(1):
                if not Post.objects.filter(slug=self.slug).exists():
                    break
                # If slug exists, append a number to the slug
                self.slug = f'{slugify(self.title)}-{x}'
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title
        
        

class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reference = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    email = models.EmailField()
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment by {self.user.username} for {self.amount}"
        
        

class ProcessAccount(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  nin = models.CharField(unique=True, max_length=15, null=False, blank=False)
  
  def __str__(self):
    return f"{self.user.username} - {self.nin}"
    

class PasswordReset(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE)
  random_code = models.CharField(max_length=15, null=True, blank=True)
  staus = models.BooleanField(default=False)
  is_send = models.BooleanField(default=False)
  is_verify = models.BooleanField(default=False)
  
  def __str__(self):
    return self.user.username