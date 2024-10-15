import requests


def airtime_process(phone,network, amount):
  url = 'https://inlomax.com/api/airtime'
  api_key = 'ti2bjrbl5lt7fojojwvn1pln1lqykvboe3wwhy99'
  headers = {
      'Authorization': f'Token {api_key}',
      'Content-Type': 'application/json'
  }
  serviceId = {
    "mtn":1,
    "airtel":2,
    "glo":3,
    "9mobile":4
  }
  data = {
      'serviceID':serviceId[network],
      "amount":amount,
      'mobileNumber': f"{phone}"
  }
  try:
    response = requests.post(url, headers=headers, json=data)
    print(response.json())
    response.raise_for_status()  # This will raise an HTTPError for bad responses
    return response.json()
  except requests.exceptions.RequestException as e:
    print("Something went wrong, try again.")
    print(f"Error: {e}")
    return {"error": str(e)}