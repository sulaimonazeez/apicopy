import requests

class ProcessPayment:
  def __init__(self):
    self.data_plans = {
      "airtel": {
       "corporate": [
          ["AIRTEL 500MB CORPORATE - 30 Days", 25],
          ["AIRTEL 1GB CORPORATE - 30 Days", 26],
          ["AIRTEL 2GB CORPORATE - 30 Days", 27],
          ["AIRTEL 5GB CORPORATE - 30 Days", 28],
          ["AIRTEL 10GB CORPORATE - 30 Days", 29]
       ],
       "promo": [
          ["AIRTEL 100MB PROMO - 1 Day", 104],
          ["AIRTEL 300MB PROMO - 2 Days", 105],
          ["AIRTEL 1GB PROMO - 2 Days", 111],
          ["AIRTEL 2GB PROMO - 2 Days", 112],
          ["AIRTEL 3GB PROMO - 7 Days", 106],
          ["AIRTEL 4GB PROMO - 30 Days", 107],
          ["AIRTEL 10GB PROMO - 30 Days", 108],
          ["AIRTEL 15GB PROMO - 30 Days", 109]
       ]
     },
    "mtn": {
      "sme": [
          ["MTN 500MB SME - 30 Days", 10],
          ["MTN 1GB SME - 30 Days", 11],
          ["MTN 2GB SME - 30 Days", 12],
          ["MTN 3GB SME - 30 Days", 13],
          ["MTN 5GB SME - 30 Days", 14],
          ["MTN 10GB SME - 30 Days", 59]
      ],
      "corporate": [
          ["MTN 500MB CORPORATE - 30 Days", 15],
          ["MTN 1GB CORPORATE - 30 Days", 16],
          ["MTN 2GB CORPORATE - 30 Days", 17],
          ["MTN 3GB CORPORATE - 30 Days", 18],
          ["MTN 5GB CORPORATE - 30 Days", 19],
          ["MTN 10GB CORPORATE - 30 Days", 60]
      ]
    },
    "glo": {
      "corporate": [
        ["GLO 500MB CORPORATE - 30 Days", 35],
        ["GLO 1GB CORPORATE - 30 Days", 36],
        ["GLO 2GB CORPORATE - 30 Days", 37],
        ["GLO 3GB CORPORATE - 30 Days", 38],
        ["GLO 5GB CORPORATE - 30 Days", 39],
        ["GLO 10GB CORPORATE - 30 Days", 40]
      ]
    },
    "mobile9": {
      "corporate": [
        ["9MOBILE 500MB CORPORATE - 30 Days", 68],
        ["9MOBILE 1GB CORPORATE - 30 Days", 69],
        ["9MOBILE 2GB CORPORATE - 30 Days", 71],
        ["9MOBILE 3GB CORPORATE - 30 Days", 72],
        ["9MOBILE 4GB CORPORATE - 30 Days", 73],
        ["9MOBILE 5GB CORPORATE - 30 Days", 75],
        ["9MOBILE 10GB CORPORATE - 30 Days", 76]
      ]
     }
    }
  def process_data(self, networkType, dataType ,dataAmount):
    checkers = self.data_plans.get(networkType.lower(), {}).get(dataType.lower(), [])
    if checkers is not None:
      for plans in checkers:
        if (plans[0] == dataAmount):
          return plans[1]
    return "No Plan Fund"
    
    
  def make_request(self, id: int, phone: str) -> dict:
    url = 'https://inlomax.com/api/data'
    api_key = 'ti2bjrbl5lt7fojojwvn1pln1lqykvboe3wwhy99'
    headers = {
        'Authorization': f'Token {api_key}',
        'Content-Type': 'application/json'
    }
    data = {
        'serviceID': str(id),
        'mobileNumber': f"{phone}"
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()  # This will raise an HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Something went wrong, try again.")
        print(f"Error: {e}")
        return {"error": str(e)}
    
    
    
    