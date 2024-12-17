import jwt
from datetime import datetime, timedelta
from config.config import auth_jwt_config
import cv2 
import numpy as np 
import matplotlib.pyplot as plt 
from math import radians, cos, sin, sqrt, atan2

class JWTUtils:
    def __init__(self):
        self.secret_key = auth_jwt_config['JWT_SECRET_KEY']
        self.algorithm = auth_jwt_config['JWT_ALGORITHM']
        self.expiry_delta = auth_jwt_config['JWT_EXPIRATION_DELTA']
        self.refresh_expiry_delta = auth_jwt_config['JWT_REFRESH_EXPIRATION_DELTA']

    def generate_jwt_tokens(self, _id, username, email,role):
        access_payload = {
            '_id': _id,
            'role': role,
            'username': username,
            'email': email,
            'exp': datetime.utcnow() + self.expiry_delta
        }
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm).decode('utf-8')

        refresh_payload = {
            '_id': _id,
            'role': role,
            'username': username,
            'email': email,
            'exp': datetime.utcnow() + self.refresh_expiry_delta
        }
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm).decode('utf-8')

        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

    def decode_jwt_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        

  
def count_logs(image_path):
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError(f"Image not found or unable to read: {image_path}")
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (11, 11), 0)
    canny = cv2.Canny(blur, 30, 150, 3)
    dilated = cv2.dilate(canny, (1, 1), iterations=0)
    cnt, hierarchy = cv2.findContours(dilated.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)
    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    cv2.drawContours(rgb, cnt, -1, (0, 255, 0), 2)
    
    return len(cnt)

def check_the_post_under_required_lat_long(lat1, lon1, lat2, lon2):
    R = 6371000
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2 #haversine 
    c = 2 * atan2(sqrt(a), sqrt(1 - a)) #angular distance between 2 radians on earth

    distance = R * c #into meters
    return distance < 5

import cv2
import pytesseract
import os

def process_vehicle_number_plate(image_path, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    image = cv2.imread(image_path)

    if image is None:
        return None, "Error: Could not load image. Check the file path."

    cv2.imwrite(os.path.join(output_dir, "original_image.png"), image)

    image = cv2.resize(image, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (5, 5), 0)

    cv2.imwrite(os.path.join(output_dir, "gray_image.png"), gray)

    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )

    cv2.imwrite(os.path.join(output_dir, "threshold_image.png"), thresh)

    edges = cv2.Canny(thresh, 100, 200)
    cv2.imwrite(os.path.join(output_dir, "edges.png"), edges)

    contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

    number_plate_found = False
    detected_number = None
    for contour in contours:
        approx = cv2.approxPolyDP(contour, 0.018 * cv2.arcLength(contour, True), True)
        if len(approx) == 4:
            x, y, w, h = cv2.boundingRect(approx)

            if w < 50 or h < 20:
                continue

            roi = thresh[y:y+h, x:x+w]
            roi_resized = cv2.resize(roi, (300, 100))

            cv2.rectangle(image, (x, y), (x + w, y + h), (0, 255, 0), 2)
            cv2.imwrite(os.path.join(output_dir, "detected_rectangle.png"), image)
            cv2.imwrite(os.path.join(output_dir, "roi.png"), roi)
            cv2.imwrite(os.path.join(output_dir, "roi_resized.png"), roi_resized)

            roi_cleaned = cv2.GaussianBlur(roi_resized, (3, 3), 0)
            roi_inverted = cv2.bitwise_not(roi_cleaned)
            cv2.imwrite(os.path.join(output_dir, "roi_cleaned.png"), roi_inverted)

            text = pytesseract.image_to_string(
                roi_inverted, config='--psm 8 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            )

            detected_number = text.strip()
            number_plate_found = True
            break

    if not number_plate_found:
        return {
            "success": False,
            "message": "No number plate detected."
        }
    return {
        "success": True,
        "message": "Number plate detected successfully.",
        "number": detected_number
    }
