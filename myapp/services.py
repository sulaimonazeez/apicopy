import requests
from django.conf import settings
import logging
import json
logger = logging.getLogger(__name__)
class PayVesselService:
    @staticmethod
    def generate_virtual_account(user, phone):
        headers = {
          'api-key': settings.PAYVESSEL_API_KEY,
          'api-secret': f'Bearer {settings.PAYVESSEL_SECRET_KEY}',
         'Content-Type': 'application/json'
}
        data = {
        "account_type": "STATIC",
        "email": user.email,
        "name": f"{user.first_name} {user.last_name}",
        "phoneNumber": f"{phone}",
        "bankcode": [120001],
        "businessid": settings.BUSINESS_ID
       }
        response = requests.post(settings.PAYVESSEL_BASE_URL, headers=headers, data=json.dumps(data))
        response_data = response.json()
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response_data}")

        if response.status_code == 201 or response.status_code == 200:
            return response_data
        else:
            error_message = response_data.get('message', 'Unknown error')
            logger.error(f"PayVessel API error: {error_message}")
            raise Exception(f"PayVessel API error: {error_message}")
            
            


class RegenerateAccount:
    @staticmethod
    def generate_virtual_account(user, phone, nin):
        headers = {
          'api-key': settings.PAYVESSEL_API_KEY,
          'api-secret': f'Bearer {settings.PAYVESSEL_SECRET_KEY}',
         'Content-Type': 'application/json'
}
        data = {
        "account_type": "STATIC",
        "email": user.email,
        "name": f"{user.first_name} {user.last_name}",
        "phoneNumber": f"{phone}",
        "bankcode": [120001],
        "businessid": settings.BUSINESS_ID,
        "nin":nin
       }
        response = requests.post(settings.PAYVESSEL_BASE_URL, headers=headers, data=json.dumps(data))
        response_data = response.json()
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response_data}")

        if response.status_code == 201 or response.status_code == 200:
            return response_data
        else:
            error_message = response_data.get('message', 'Unknown error')
            logger.error(f"PayVessel API error: {error_message}")
            raise Exception(f"PayVessel API error: {error_message}")
            
            
            
  

class RegenerateAccountBvn:
    @staticmethod
    def generate_virtual_account(user, phone, bvn):
        headers = {
          'api-key': settings.PAYVESSEL_API_KEY,
          'api-secret': f'Bearer {settings.PAYVESSEL_SECRET_KEY}',
         'Content-Type': 'application/json'
}
        data = {
        "account_type": "STATIC",
        "email": user.email,
        "name": f"{user.first_name} {user.last_name}",
        "phoneNumber": f"{phone}",
        "bankcode": [120001],
        "businessid": settings.BUSINESS_ID,
        "bvn":bvn
       }
        response = requests.post(settings.PAYVESSEL_BASE_URL, headers=headers, data=json.dumps(data))
        response_data = response.json()
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response data: {response_data}")

        if response.status_code == 201 or response.status_code == 200:
            return response_data
        else:
            error_message = response_data.get('message', 'Unknown error')
            logger.error(f"PayVessel API error: {error_message}")
            raise Exception(f"PayVessel API error: {error_message}")
            
            
            
  


