from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import VirtualsAccountings, UserProfiles,WalletFundings, Balance, Payment
from django.db.models import F
from .services import PayVesselService
import logging

logger = logging.getLogger(__name__)
@receiver(post_save, sender=WalletFundings)
def update_user_balance(sender, instance, created, **kwargs):
    if created:
        Balance.objects.filter(user__email=instance.user).update(balance=F('balance') + instance.settle_amount)
        
@receiver(post_save, sender=Payment)
def update_user_balance_paystack(sender, instance, created, **kwargs):
  if created:
    if instance.status == "success":
      Balance.objects.filter(user__email=instance.user.email ).update(balance=F('balance') + instance.amount)
 
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfiles.objects.create(user=instance)
    instance.userprofiles.save()
