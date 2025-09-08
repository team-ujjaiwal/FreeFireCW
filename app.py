from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import data_pb2

app = Flask(__name__)

# AES Keys
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Region URLs
region_urls = {
    "IND": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "BR": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "US": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SAC": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "NA": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
}
default_url = "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"

# Token Generator
def generate_token(uid, password):
    try:
        r = requests.get(f"https://100067.vercel.app/token?uid={uid}&password={password}")
        return r.json().get("token", "")
    except:
        return ""

# Protobuf + AES Encrypted Payload
def get_encrypted_payload(bio):
    data = data_pb2.Data()
    data.field_2 = 17
    data.field_5.CopyFrom(data_pb2.EmptyMessage())
    data.field_6.CopyFrom(data_pb2.EmptyMessage())
    data.field_8 = bio
    data.field_9 = 1
    data.field_11.CopyFrom(data_pb2.EmptyMessage())
    data.field_12.CopyFrom(data_pb2.EmptyMessage())
    padded = pad(data.SerializeToString(), AES.block_size)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)

@app.route('/bio', methods=['GET'])
def change_bio():
    region = request.args.get('region', '').upper()
    bio = request.args.get('bio')
    jwt = request.args.get('token', '')
    uid = request.args.get('uid', '')
    password = request.args.get('password', '')

    if not bio or not region:
        return jsonify({"error": "Missing bio or region"}), 400

    if not jwt:
        if not uid or not password:
            return jsonify({"error": "Provide either JWT or UID + Password"}), 400
        jwt = generate_token(uid, password)
        if not jwt:
            return jsonify({"error": "Token generation failed"}), 401

    url = region_urls.get(region, default_url)
    payload = get_encrypted_payload(bio)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 11)",
        "Accept-Encoding": "gzip"
    }

    res = requests.post(url, headers=headers, data=payload)

    if res.status_code == 200:
        return jsonify({"status": "success", "region": region, "bio": bio})
    else:
        return jsonify({"status": "failed", "code": res.status_code, "reason": res.text})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)