from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
import logging
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
API_URL = "https://client.ind.freefiremobile.com/GetWishListItems"
TOKEN_URL = "https://aditya-jwt-v9op.onrender.com/token?uid=3959788424&password=513E781858206A2994D10F7E767C4F1567549C7A4343488663B6EBC9A0880E31"
ITEM_IMAGE_API = "https://freefireinfo.vercel.app/icon?id={item_id}"

# Configure logging (console only — safe for Vercel, AWS, etc.)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Cache setup
token_cache = {
    'token': None,
    'expiry': 0,
    'account_info': None
}

# Rate limiting
request_tracker = {}

# Thread pool for parallel image fetching
executor = ThreadPoolExecutor(max_workers=10)

# Helper Functions
def aes_cbc_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size, style='pkcs7'))

def aes_cbc_decrypt(ciphertext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size, 'pkcs7')

def encode_varint(value: int) -> bytes:
    buf = b""
    while True:
        towrite = value & 0x7F
        value >>= 7
        if value:
            buf += bytes((towrite | 0x80,))
        else:
            buf += bytes((towrite,))
            break
    return buf

def decode_varint(data, index):
    result, shift, length = 0, 0, 0
    while index + length < len(data):
        byte = data[index + length]
        result |= (byte & 0x7F) << shift
        length += 1
        if not (byte & 0x80):
            return result, index + length
        shift += 7
    raise IndexError("Invalid varint data")

def create_request_payload(target_uid: int) -> bytes:
    return b'\x08' + encode_varint(target_uid)

def get_jwt_token():
    try:
        current_time = time.time()
        if token_cache['token'] and token_cache['expiry'] > current_time:
            return token_cache['token'], token_cache['account_info']
            
        response = requests.get(TOKEN_URL, timeout=5)
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            if token:
                ttl = data.get("ttl", 28800)
                token_cache['token'] = token
                token_cache['expiry'] = current_time + ttl - 60
                token_cache['account_info'] = {
                    "accountId": data.get("accountId"),
                    "ipRegion": data.get("ipRegion"),
                    "lockRegion": data.get("lockRegion"),
                    "serverUrl": data.get("serverUrl")
                }
                return token, token_cache['account_info']
        
        logging.error(f"Failed to fetch token: HTTP {response.status_code}")
        return None, None
        
    except Exception as e:
        logging.error(f"Token fetch error: {str(e)}")
        return None, None

def parse_wishlist_response(data):
    item_ids = []
    index = 0
    while index < len(data):
        try:
            tag, index = decode_varint(data, index)
            field, wire_type = tag >> 3, tag & 7

            if field == 1 and wire_type == 0:
                item_id, index = decode_varint(data, index)
                item_ids.append(item_id)
            elif field == 1 and wire_type == 2:
                length, index = decode_varint(data, index)
                sub_data = data[index:index+length]
                index += length
                item_ids.extend(parse_wishlist_response(sub_data))
            else:
                if wire_type == 0:
                    _, index = decode_varint(data, index)
                elif wire_type == 1:
                    index += 8
                elif wire_type == 2:
                    length, index = decode_varint(data, index)
                    index += length
                elif wire_type == 5:
                    index += 4
        except IndexError:
            break
    return item_ids

def fetch_item_image(item_id):
    try:
        url = ITEM_IMAGE_API.format(item_id=item_id)
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.url
        return None
    except Exception as e:
        logging.warning(f"Failed to fetch image for item {item_id}: {str(e)}")
        return None

def process_items(item_ids):
    futures = [executor.submit(fetch_item_image, item_id) for item_id in item_ids]
    results = [future.result() for future in futures]
    
    formatted_items = []
    for item_id, image_url in zip(item_ids, results):
        formatted_items.append({
            "item_id": str(item_id),
            "image_url": image_url if image_url else "Not available"
        })
    
    return formatted_items

@app.route('/wishlist', methods=['GET'])
def get_wishlist():
    client_ip = request.remote_addr
    current_time = time.time()
    
    if client_ip in request_tracker:
        request_tracker[client_ip] = [t for t in request_tracker[client_ip] if current_time - t < 60]
        if len(request_tracker[client_ip]) >= 10:
            return jsonify({
                "status": "error",
                "code": 429,
                "message": "Too many requests. Please try again later.",
                "timestamp": datetime.utcnow().isoformat()
            }), 429
    else:
        request_tracker[client_ip] = []
    
    request_tracker[client_ip].append(current_time)
    
    # Get target UID from query parameters
    target_uid = request.args.get('uid')
    if not target_uid or not target_uid.isdigit():
        return jsonify({
            "status": "error",
            "code": 400,
            "message": "Invalid UID provided. Please provide a valid numeric UID.",
            "timestamp": datetime.utcnow().isoformat()
        }), 400

    jwt_token, account_info = get_jwt_token()
    if not jwt_token:
        return jsonify({
            "status": "error",
            "code": 500,
            "message": "Failed to authenticate with the service. Please try again later.",
            "timestamp": datetime.utcnow().isoformat()
        }), 500

    headers = {
        'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
        'Authorization': f'Bearer {jwt_token}',
        'X-Ga': 'v1 1',
        'Releaseversion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Unity-Version': '2022.3.47f1',
        'Account-Id': account_info.get("accountId", ""),
        'Region': account_info.get("lockRegion", "IND")
    }

    try:
        # Prepare and send request
        payload = create_request_payload(int(target_uid))
        encrypted = aes_cbc_encrypt(payload)
        response = requests.post(API_URL, headers=headers, data=encrypted, timeout=10)

        if response.status_code == 200 and response.content:
            try:
                decrypted_data = aes_cbc_decrypt(response.content)
                data_to_parse = decrypted_data
            except (ValueError, IndexError) as e:
                logging.warning(f"Decryption failed, trying raw data: {str(e)}")
                data_to_parse = response.content

            item_ids = parse_wishlist_response(data_to_parse)
            formatted_items = process_items(item_ids)
            
            # Format the response as requested
            item_ids_str = ", ".join([str(item['item_id']) for item in formatted_items])
            image_urls_str = ", ".join([item['image_url'] for item in formatted_items if item['image_url'] != "Not available"])
            
            output = {
                "metadata": {
                    "account_used": account_info.get("accountId"),
                    "region": account_info.get("lockRegion"),
                    "requested_uid": int(target_uid),
                    "server": account_info.get("serverUrl")
                },
                "results": [{
                    "wishlist": [{
                        "Count": len(item_ids),
                        "retrieved_at": datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
                        "item_id": item_ids_str,
                        "image_url": [image_urls_str]
                    }]
                }]
            }
            
            return jsonify(output)
            
        return jsonify({
            "status": "error",
            "code": response.status_code,
            "message": f"No data received from server (HTTP {response.status_code})",
            "timestamp": datetime.utcnow().isoformat()
        }), response.status_code
        
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        return jsonify({
            "status": "error",
            "code": 500,
            "message": "An internal server error occurred",
            "error_details": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    token_status = "healthy"
    try:
        test_resp = requests.get(TOKEN_URL, timeout=3)
        if test_resp.status_code != 200:
            token_status = f"unhealthy (HTTP {test_resp.status_code})"
    except Exception as e:
        token_status = f"unreachable ({str(e)})"
    
    return jsonify({
        "status": "healthy",
        "service": "FreeFire Wishlist API",
        "version": "1.2",
        "token_service": token_status,
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)