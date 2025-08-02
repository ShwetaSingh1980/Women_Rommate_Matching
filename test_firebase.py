import firebase_admin
from firebase_admin import credentials

try:
    cred = credentials.Certificate('config/firebase_config.json')
    firebase_admin.initialize_app(cred)
    print("Firebase connected successfully!")
except Exception as e:
    print(f"Firebase error: {e}")
