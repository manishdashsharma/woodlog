from dotenv import load_dotenv
import os
from datetime import timedelta

load_dotenv(f"{os.getcwd()}/.env")
# load_dotenv("/home/woodlogcount/woodlog-count/.env")

config = {
    "apiKey": os.getenv("apiKey"),
    "authDomain": os.getenv("authDomain"),
    "databaseURL": os.getenv("databaseURL"),
    "projectId": os.getenv("projectId"),
    "storageBucket": os.getenv("storageBucket"),
    "messagingSenderId": os.getenv("messagingSenderId"),
    "appId": os.getenv("appId"),
    "measurementId": os.getenv("measurementId")
}
print(config)

auth_jwt_config = {
    'JWT_SECRET_KEY': os.getenv("JWT_SECRET_KEY"),
    'JWT_ALGORITHM': os.getenv("JWT_ALGORITHM"),
    'JWT_ALLOW_REFRESH': True,
    'JWT_EXPIRATION_DELTA': timedelta(days=10),
    'JWT_REFRESH_EXPIRATION_DELTA': timedelta(days=7),
}