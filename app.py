from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import data_pb2  # Import the generated protobuf module

app = Flask(__name__)

region_urls = {
    "IND": "https://client.ind.freefiremobile.com/SetPlayerGalleryShowInfo",
    "BR": "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo",
    "US": "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo",
    "SAC": "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo",
    "NA": "https://client.us.freefiremobile.com/SetPlayerGalleryShowInfo",
    "DEFAULT": "https://clientbp.ggblueshark.com/SetPlayerGalleryShowInfo"
}

key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

@app.route('/add_items', methods=['GET'])
def add_items():
    jwt_token = request.args.get("jwt")
    region = request.args.get("region", "DEFAULT")
    items = [int(request.args.get(f"item{i+1}")) for i in range(15) if request.args.get(f"item{i+1}")]

    if not jwt_token or len(items) != 15:
        return jsonify({"error": "Missing JWT or item1 to item15"}), 400

    # Use the generated protobuf class
    data = data_pb2.MainMessage()
    data.field_1 = 1
    container1 = data.field_2.add()
    container1.field_1 = 1

    template = [
        {"field_1": 2, "field_4": 1, "field_6": {"field_6": items[0]}},
        {"field_1": 2, "field_4": 1, "field_5": 4, "field_6": {"field_6": items[1]}},
        {"field_1": 2, "field_4": 1, "field_5": 2, "field_6": {"field_6": items[2]}},
        {"field_1": 13, "field_3": 1, "field_6": {"field_6": items[3]}},
        {"field_1": 13, "field_3": 1, "field_4": 2, "field_6": {"field_6": items[4]}},
        {"field_1": 13, "field_3": 1, "field_5": 2, "field_6": {"field_6": items[5]}},
        {"field_1": 13, "field_3": 1, "field_5": 4, "field_6": {"field_6": items[6]}},
        {"field_1": 13, "field_3": 1, "field_4": 2, "field_5": 2, "field_6": {"field_6": items[7]}},
        {"field_1": 13, "field_3": 1, "field_4": 2, "field_5": 4, "field_6": {"field_6": items[8]}},
        {"field_1": 13, "field_3": 1, "field_4": 4, "field_6": {"field_6": items[9]}},
        {"field_1": 13, "field_3": 1, "field_4": 4, "field_5": 2, "field_6": {"field_6": items[10]}},
        {"field_1": 13, "field_3": 1, "field_4": 4, "field_5": 4, "field_6": {"field_6": items[11]}},
        {"field_1": 13, "field_3": 1, "field_4": 6, "field_6": {"field_6": items[12]}},
        {"field_1": 13, "field_3": 1, "field_4": 6, "field_5": 2, "field_6": {"field_6": items[13]}},
        {"field_1": 13, "field_3": 1, "field_4": 6, "field_5": 4, "field_6": {"field_6": items[14]}},
    ]

    for item_data in template:
        item = container1.field_2.add()
        item.field_1 = item_data["field_1"]
        if "field_3" in item_data: item.field_3 = item_data["field_3"]
        if "field_4" in item_data: item.field_4 = item_data["field_4"]
        if "field_5" in item_data: item.field_5 = item_data["field_5"]
        item.field_6.field_6 = item_data["field_6"]["field_6"]

    container2 = data.field_2.add()
    container2.field_1 = 9
    it1 = container2.field_2.add()
    it1.field_4 = 3
    it1.field_6.field_14 = 3048205855
    it2 = container2.field_2.add()
    it2.field_4 = 3
    it2.field_5 = 3
    it2.field_6.field_14 = 3048205855

    data_bytes = data.SerializeToString()
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    url = region_urls.get(region.upper(), region_urls["DEFAULT"])
    response = requests.post(url, headers=headers, data=encrypted_data)

    return jsonify({"status": response.status_code, "response": response.text})

if __name__ == '__main__':
    app.run(debug=True, port=5000)