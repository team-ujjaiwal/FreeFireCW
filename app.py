from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from GetWishListItems_pb2 import CSGetWishListItemsRes
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
from datetime import datetime

app = Flask(__name__)
jwt_token = None
jwt_lock = threading.Lock()

# Server configuration mapping
SERVER_CONFIG = {
    "IND": "https://100067.vercel.app/token?uid=3828066210&password=C41B0098956AE7B79F752FCA873C747060C71D3C17FBE4794F5EB9BD71D4DA95",
        "BR": "https://100067.vercel.app/token?uid=3943737998&password=92EB4C721DB698B17C1BF61F8F7ECDEC55D814FB35ADA778FA5EE1DC0AEAEDFF",
        "US": "https://100067.vercel.app/token?uid=3943737998&password=92EB4C721DB698B17C1BF61F8F7ECDEC55D814FB35ADA778FA5EE1DC0AEAEDFF",
        "SAC": "https://100067.vercel.app/token?uid=3943737998&password=92EB4C721DB698B17C1BF61F8F7ECDEC55D814FB35ADA778FA5EE1DC0AEAEDFF",
        "NA": "https://100067.vercel.app/token?uid=3943737998&password=92EB4C721DB698B17C1BF61F8F7ECDEC55D814FB35ADA778FA5EE1DC0AEAEDFF",
        "default": "https://100067.vercel.app/token?uid=3943739516&password=BFA0A0D9DF6D4EE1AA92354746475A429D775BCA4D8DD822ECBC6D0BF7B51886"
    }    
}

#image_base_url
"image_base_url": "https://www.dl.cdn.freefiremobile.com/icons/"

def convert_timestamp(release_time):
    return datetime.utcfromtimestamp(release_time).strftime('%Y-%m-%d %H:%M:%S')

def extract_token_from_response(data, region):
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BR", "US", "SAC", "NA"]:
        if isinstance(data, dict) and 'token' in data:
            return data['token']
    else: 
        # New JWT API response format
        if isinstance(data, dict) and 'token' in data:
            return data['token']
        elif data.get('status') == 'success':
            return data.get('token')
    return None

def get_jwt_token_sync(region):
    global jwt_token
    config = SERVER_CONFIG.get(region, SERVER_CONFIG["default"])
    url = config["token_url"]
    
    with jwt_lock:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                token = extract_token_from_response(data, region)
                if token:
                    jwt_token = token
                    print(f"JWT Token for {region} updated successfully: {token[:50]}...")
                    return jwt_token
                else:
                    print(f"Failed to extract token from response for {region}. Response: {data}")
            else:
                print(f"Failed to get JWT token for {region}: HTTP {response.status_code}")
        except Exception as e:
            print(f"Request error for {region}: {e}")   
    return None

def ensure_jwt_token_sync(region):
    global jwt_token
    if not jwt_token:
        print(f"JWT token for {region} is missing. Attempting to fetch a new one...")
        return get_jwt_token_sync(region)
    return jwt_token

def jwt_token_updater(region):
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)

def get_api_endpoint(region):
    config = SERVER_CONFIG.get(region, SERVER_CONFIG["default"])
    return config["api_endpoint"]

def get_image_base_url(region):
    config = SERVER_CONFIG.get(region, SERVER_CONFIG["default"])
    return config["image_base_url"]

key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, region):
    global jwt_token    
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")    
    endpoint = get_api_endpoint(region)    
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
    }    
    try:
        data = bytes.fromhex(idd)
        response = requests.post(
            endpoint,
            headers=headers,
            data=data,
            timeout=10
        )
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API request to {endpoint} failed: {e}")
        raise

@app.route('/wishlist', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
            
        threading.Thread(target=jwt_token_updater, args=(region,), daemon=True).start()
        
        # إنشاء الرسالة Protocol Buffer
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response_hex = apis(encrypted_hex, region)         
        if not api_response_hex:
            return jsonify({"error": "Empty response from API"}), 400
        api_response_bytes = bytes.fromhex(api_response_hex)
        decoded_response = CSGetWishListItemsRes()
        decoded_response.ParseFromString(api_response_bytes)
        
        # Get image base URL for the region
        image_base_url = get_image_base_url(region)
        
        wishlist = [
            {
                "item_id": item.item_id, 
                "release_time": convert_timestamp(item.release_time),
                "image_url": f"{image_base_url}{item.item_id}.png"
            }
            for item in decoded_response.items
        ]            
        return jsonify({"uid": uid, "wishlist": wishlist})  
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

if __name__ == "__main__":
    ensure_jwt_token_sync("default")
    app.run(host="0.0.0.0", port=5552)