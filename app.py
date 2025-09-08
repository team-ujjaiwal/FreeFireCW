from flask import Flask, request, jsonify
import jwt
import requests
import RemoveFriend_Req_pb2
import RequestAddingFriend_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# AES Key and IV (hardcoded as per FF API requirement)
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Region URLs mapping
region_urls = {
    "IND": "https://client.ind.freefiremobile.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "US": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "NA": "https://client.us.freefiremobile.com/",
}
default_url = "https://clientbp.ggblueshark.com/"

def encrypt_message(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return encrypted

def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except Exception as e:
        return None

def get_base_url(region):
    return region_urls.get(region.upper(), default_url)

def remove_friend(author_uid, target_uid, token, region):
    try:
        message = RemoveFriend_Req_pb2.RemoveFriend()
        message.AuthorUid = int(author_uid)
        message.TargetUid = int(target_uid)
        serialized = message.SerializeToString()
        encrypted_bytes = encrypt_message(serialized)

        base_url = get_base_url(region)
        url = f"{base_url}RemoveFriend"
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }

        response = requests.post(url, data=encrypted_bytes, headers=headers)

        if response.status_code == 200:
            return {"status": "success", "message": "Friend removed successfully"}
        else:
            return {"status": "fail", "code": response.status_code, "response": response.text}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_friend_request(author_uid, target_uid, token, region):
    try:
        message = RequestAddingFriend_pb2.RequestAddingFriend()
        message.AuthorUid = int(author_uid)
        message.TargetUid = int(target_uid)
        serialized = message.SerializeToString()
        encrypted_bytes = encrypt_message(serialized)

        base_url = get_base_url(region)
        url = f"{base_url}RequestAddingFriend"
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }

        response = requests.post(url, data=encrypted_bytes, headers=headers)

        if response.status_code == 200:
            return {"status": "success", "message": "Friend request sent successfully"}
        else:
            return {"status": "fail", "code": response.status_code, "response": response.text}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.route('/remove_request', methods=['GET'])
def remove_friend_api():
    token = request.args.get('token')
    target_uid = request.args.get('uid')
    region = request.args.get('region', 'IND')

    if not token or not target_uid:
        return jsonify({"status": "fail", "message": "Missing 'token' or 'uid'"}), 400

    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "fail", "message": "Unable to decode author UID from token"}), 400

    result = remove_friend(author_uid, target_uid, token, region)
    return jsonify(result)

@app.route('/send_request', methods=['GET'])
def send_friend_request_api():
    token = request.args.get('token')
    target_uid = request.args.get('uid')
    region = request.args.get('region', 'IND')

    if not token or not target_uid:
        return jsonify({"status": "fail", "message": "Missing 'token' or 'uid'"}), 400

    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "fail", "message": "Unable to decode author UID from token"}), 400

    result = send_friend_request(author_uid, target_uid, token, region)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5005)