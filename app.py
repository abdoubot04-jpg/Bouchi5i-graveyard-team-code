import os, json, requests, time, ssl, random, socket, threading, base64, struct, urllib3
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from protobuf_decoder.protobuf_decoder import Parser
from flask import Flask, request, jsonify
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

xK, xV = b'Yg&tc%DEuh6%Zc^8', b'6oyZDr22E3ychjM%'

app = Flask(__name__)

# ------------------------------------------------------------------
#  ACCOUNT CONFIG  (عدّل هنا: أضف/احذف الحسابات كما تشاء)
# ------------------------------------------------------------------
ACCOUNTS = [
    ("8459707082", "B90F2A343704B68C31B3262630CDB10F5AF061003F36411C4B0CDD84EAD323DA"),
    ("8459734304", "D06B367526E0D915C4CC03307E9EE35D932469885A6340193182D539AE41B69A"),
]

# ------------------------------------------------------------------
#  GLOBAL STATE  —  فريق لكل فريق_code
# ------------------------------------------------------------------
SESSIONS = {}                 # acc_uid -> session dict
SESSIONS_LOCK = threading.Lock()

TEAMS = {}                    # team_code -> dict(threads=[], stop_event, stats)
TEAMS_LOCK = threading.Lock()

# ==================================================================
#  PROTOBUF / CRYPTO HELPERS  (كما في الأصل)
# ==================================================================
def EnV_VaRiAnT(n):
    d = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        d.append(b)
        if not n:
            break
    return bytes(d)

def ProToBuF(Fields):
    p = bytearray()
    for f, v in Fields.items():
        if isinstance(v, bool):
            p.extend(EnV_VaRiAnT((f << 3) | 0)); p.extend(EnV_VaRiAnT(1 if v else 0))
        elif isinstance(v, int):
            p.extend(EnV_VaRiAnT((f << 3) | 0)); p.extend(EnV_VaRiAnT(v))
        elif isinstance(v, str):
            d = v.encode(); p.extend(EnV_VaRiAnT((f << 3) | 2)); p.extend(EnV_VaRiAnT(len(d))); p.extend(d)
        elif isinstance(v, (bytes, bytearray)):
            d = bytes(v); p.extend(EnV_VaRiAnT((f << 3) | 2)); p.extend(EnV_VaRiAnT(len(d))); p.extend(d)
    return bytes(p)

def Read_VaRiAnT(data, pos):
    result = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def Parse_ProToBuF(data):
    fields = {}; pos = 0; n = len(data)
    while pos < n:
        try:
            key, pos = Read_VaRiAnT(data, pos)
        except:
            break
        fn = key >> 3; wt = key & 0x07
        try:
            if wt == 0:
                val, pos = Read_VaRiAnT(data, pos)
            elif wt == 2:
                ln, pos = Read_VaRiAnT(data, pos)
                val = data[pos:pos + ln]; pos += ln
            elif wt == 5:
                val = data[pos:pos + 4]; pos += 4
            elif wt == 1:
                val = data[pos:pos + 8]; pos += 8
            else:
                break
        except:
            break
        fields.setdefault(fn, []).append(val)
    return fields

def Ua():
    return random.choice(['4.0.18P6','4.0.19P7','4.0.20P1','4.1.0P3','4.1.5P2','4.2.1P8','4.2.3P1','5.0.1B2','5.0.2P4','5.1.0P1','5.2.0B1','5.2.5P3','5.3.0B1','5.3.2P2','5.4.0P1','5.4.3B2','5.5.0P1','5.5.2P3'])

def EnC_PacKeT(HeX, K, V):
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()

def DEc_PacKeT(HeX, K, V):
    return unpad(AES.new(K, AES.MODE_CBC, V).decrypt(bytes.fromhex(HeX)), 16).hex()

def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F; N >>= 7
        if N:
            BesTo |= 0x80
        H.append(BesTo)
        if not N:
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    nested_packet = CrEaTe_ProTo(item)
                    packet.extend(CrEaTe_LenGTh(field, nested_packet))
    return packet

def DecodE_HeX(H):
    R = hex(H); F = str(R)[2:]
    if len(F) == 1:
        F = "0" + F
        return F
    return F

def GeneRaTePk(Pk, N, K, V):
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(int(len(PkEnc) // 2))
    if len(_) == 2:
        HeadEr = N + "000000"
    elif len(_) == 3:
        HeadEr = N + "00000"
    elif len(_) == 4:
        HeadEr = N + "0000"
    elif len(_) == 5:
        HeadEr = N + "000"
    else:
        HeadEr = N + "00000"
    return bytes.fromhex(HeadEr + _ + PkEnc)

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {'wire_type': result.wire_type}
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        return json.dumps(Fix_PackEt(parsed_results))
    except:
        return None

# ==================================================================
#  PACKETS
# ==================================================================
def Join_Team(team_code, key, iv):
    fields = {1: bytes.fromhex("01090a0b121619201d2729"), 2: 40, 3: bytes.fromhex("01090a0b121619201d2729"), 4: "w\\Z]", 6: 12, 7: bytes.fromhex("01090a0b121619201d2729"), 8: "1.132.9", 9: 6, 10: 2, 11: bytes.fromhex("01090a0b121619201d2729")}
    f = {1: 4, 2: {4: bytes.fromhex("01090a0b121619201d2729"), 5: str(team_code), 6: 6, 8: 1, 9: fields, 11: {1: "IDC1", 2: 99, 3: "ME"}, 13: "ar", 16: bytes.fromhex("374f521955"), 20: [{1: 3, 2: 360}, {1: 4, 2: 391}, {1: 5, 2: 156}, {1: 29, 2: 204}, {1: 22, 2: 118}, {1: 14, 2: 139}, {1: 21}], 27: {1: 2, 2: 4}}}
    return GeneRaTePk(CrEaTe_ProTo(f).hex(), "0519", key, iv)

def SendInv(bot_uid, uid, K, V):
    fields = {1: 33, 2: {1: int(uid), 2: "ME", 3: 1, 4: 1, 6: "yyt", 7: 330, 8: 1000, 9: 100, 10: "DZ", 12: 1, 13: int(uid), 16: 1, 17: {2: 159, 4: "y[WW", 6: 11, 8: "1.118.1", 9: 3, 10: 1}, 18: 306, 19: 18, 24: 902000306, 26: {}, 27: {1: 11, 2: int(bot_uid), 3: 999}, 28: {}, 31: {1: 1, 2: 32768}, 32: 32768, 34: {1: int(bot_uid), 2: 8, 3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0519', K, V)

def Send_GhosTs(uid, name, sq, key, iv, lang="en"):
    fields = {1: 61, 2: {1: int(uid), 2: {1: int(uid), 2: 1159, 3: name, 5: 12, 6: 9999, 7: 1, 8: {2: 1, 3: 1}, 9: 3, 10: lang}, 3: sq}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0519', key, iv)

def ExiT(key, iv):
    fields = {1: 7, 2: {1: 0}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0519', key, iv)

def PyL(access_token, open_id):
    P = {}
    P[3] = time.strftime("%Y-%m-%d %H:%M:%S"); P[4]="free fire"; P[5]=1; P[7]="1.132.9"
    P[8]="Android OS 14 / API-34 (UP1A.231005.007/V816.0.15.0.UNQMIXM)"
    P[9]="Handheld"; P[10]="Grameenphone"; P[11]="CarrierDataNetwork"
    P[12]=1666; P[13]=750; P[14]="352"; P[15]="ARM64 FP ASIMD AES | 2400 | 8"
    P[16]=5563; P[17]="Mali-G57 MC2"
    P[18]="OpenGL ES 3.2 v1.r32p1-01eac0.0a0b917d9265b4c01be9925306306139"
    P[19]="Google|9cc73f7a-91f6-40f6-87ec-5b67e597eb8c"; P[20]="59.152.5.188"
    P[21]="en"; P[22]=open_id; P[23]="8"; P[24]="Handheld"
    P[25]="Xiaomi 2312DRAABI"; P[26]="BD"; P[29]=access_token; P[30]=1
    P[41]="Grameenphone"; P[42]="Cellular"
    P[57]="7428b253defc164018c604a1ebbfebdf"
    P[60]=109685; P[61]=58294; P[62]=797; P[63]=18000; P[64]=58818; P[65]=109685
    P[66]=58818; P[67]=109685; P[73]=2
    P[74]="/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/lib/arm64"
    P[76]=1
    P[77]="b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/base.apk"
    P[78]=3; P[79]=2; P[81]="64"; P[83]="2019121229"; P[85]=3; P[86]="OpenGLES2"
    P[87]=4095; P[88]=8
    P[89]=b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    P[90]="Dhaka"; P[91]="C"; P[92]=8043; P[93]="android"
    P[94]="KqsHT4XbSZhqerDNUhjbS3DxG/4+I62zQU2tZFJN91kBUICAlZ5yujshLKvjlk/KiShfKfis8EeB1PMhFHIodWPncZC4fCHYF3TcTwNj95aWY/S3"
    P[95]=111207; P[96]='{"cur_rate":[60,90,120],"support_etc2":false}'
    P[97]=1; P[98]=1; P[99]="4"; P[100]="4"; P[102]="GQ]        e"; P[103]=1
    P[104]=45174; P[105]=1
    P[106]="https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a"
    P[107]="1.9393e7b8e53e8aeb"
    return AES.new(xK, AES.MODE_CBC, xV).encrypt(pad(ProToBuF(P), 16))

# ==================================================================
#  LOGIN FLOW
# ==================================================================
def Strip_MajorLogin_Prefix(body):
    if len(body) <= 64:
        return body
    try:
        if 8 in Parse_ProToBuF(body):
            return body
    except:
        pass
    try:
        if 8 in Parse_ProToBuF(body[64:]):
            return body[64:]
    except:
        pass
    return body[64:]

def GeT_AccEss(uid, password):
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    headers = {"User-Agent": Ua(), "Content-Type": "application/json; charset=utf-8"}
    R = requests.post(url, headers=headers, json={"client_id": 100067, "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_type": 2, "device_id": "", "password": password, "response_type": "token", "uid": int(uid)}, verify=False, timeout=15)
    print(f"[{uid}] Get access => {R.status_code}")
    if R.status_code not in (200, 201):
        return None
    try:
        J = R.json()
    except:
        return None
    if J.get("code") != 0:
        return None
    d = J.get("data", {})
    return {"access_token": d.get("access_token"), "open_id": d.get("open_id")}

def MajorLogin(Payload):
    url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
    headers = {"User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)", "Accept": "*/*", "Accept-Encoding": "deflate, gzip", "X-GA-SV": str(int(time.time())), "Authorization": "Bearer ", "X-GA": "v1 1", "ReleaseVersion": "OB55", "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"}
    R = requests.post(url, headers=headers, data=Payload, verify=False, timeout=15)
    print(f"MajorLogin => {R.status_code}")
    return R.content if R.status_code in (200, 201) and R.content else None

def GeTLoginDaTa(client_url, payload, jwt):
    url = f"{client_url}/GetLoginData"
    headers = {"User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)", "Accept": "*/*", "Accept-Encoding": "deflate, gzip", "X-GA-SV": str(int(time.time())), "Authorization": f"Bearer {jwt}", "X-GA": "v1 1", "ReleaseVersion": "OB55", "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"}
    R = requests.post(url, headers=headers, data=payload, verify=False, timeout=15)
    print(f"GetLoginData => {R.status_code}")
    return R.content if R.status_code == 200 and R.content else None

def _gv(fields, n):
    v = fields.get(n)
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0]
    return v

def ExtractMajorLogin(ml_resp):
    body = Strip_MajorLogin_Prefix(ml_resp)
    f = Parse_ProToBuF(body)
    jwt_b = _gv(f, 8); url_b = _gv(f, 10); ts_v = _gv(f, 21)
    key_b = _gv(f, 22); iv_b = _gv(f, 23); acct_v = _gv(f, 1)
    jwt = None
    if isinstance(jwt_b, bytes):
        try:
            jwt = jwt_b.decode("utf-8")
        except:
            jwt = jwt_b.decode("utf-8", errors="ignore")
    elif isinstance(jwt_b, str):
        jwt = jwt_b
    url = None
    if isinstance(url_b, bytes):
        try:
            url = url_b.decode("utf-8")
        except:
            url = None
    elif isinstance(url_b, str):
        url = url_b
    ts = ts_v if isinstance(ts_v, int) else None
    acct = acct_v if isinstance(acct_v, int) else None
    if not jwt or not isinstance(key_b, bytes) or not isinstance(iv_b, bytes):
        print(f"[ML] missing fields")
        return None
    return {"jwt": jwt, "url": url, "ts": ts, "key": key_b, "iv": iv_b, "account_id": acct}

def BuildAuthToken(uid, jwt_str, ts, key, iv, mode="online"):
    ah = f"{int(uid):x}"
    if len(ah) > 16:
        raise ValueError("uid hex too long")
    ah = ah.zfill(16)
    enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(jwt_str.encode(), 16)).hex()
    th = f"{int(ts):x}"
    if len(th) % 2:
        th = "0" + th
    tsz = f"{len(enc)//2:02x}"
    pad_ = "00000" if mode == "chat" else "0000000000000"
    return f"9015{ah}{th}{pad_}{tsz}{enc}"

def _TuneSock(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

def login_account(acc_uid, acc_pass):
    td = GeT_AccEss(acc_uid, acc_pass)
    if not td:
        return None
    access_token = td["access_token"]; open_id = td["open_id"]
    if not access_token or not open_id:
        return None
    login_payload = PyL(access_token, open_id)
    ml = MajorLogin(login_payload)
    if not ml:
        return None
    ad = ExtractMajorLogin(ml)
    if not ad:
        print(f"[{acc_uid}] MajorLogin parse failed")
        return None
    jwt = ad["jwt"]; ts = ad["ts"]; key = ad["key"]; iv = ad["iv"]
    url = ad["url"] or "https://clientbp.ppmainecoonghj.com"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    account_id = ad["account_id"]
    print(f"[{acc_uid}] JWT len={len(jwt)} | ts={ts} | acct={account_id}")
    ld = GeTLoginDaTa(url, login_payload, jwt)
    if not ld:
        return None
    gl = Parse_ProToBuF(ld)
    def gv(n):
        v = gl.get(n)
        if v is None: return None
        if isinstance(v, list): v = v[0]
        return v
    def gs(n):
        v = gv(n)
        return v.decode() if isinstance(v, bytes) else v
    def gi(n):
        v = gv(n)
        return int(v) if isinstance(v, int) else None
    player_name = gs(4) or ""
    func_addr = gs(14); info_addr = gs(32)
    if not func_addr or not info_addr:
        print(f"[{acc_uid}] missing ip:port")
        return None
    ip, port = func_addr.split(":")
    ip2, port2 = info_addr.split(":")
    if not account_id:
        account_id = gi(1) or gi(5) or 0
    print(f"[{acc_uid}] BoT Is OnLiNe | {player_name} | UID: {account_id}")
    return {
        "uid": account_id, "jwt": jwt, "ts": ts, "key": key, "iv": iv,
        "ip": ip, "port": port, "ip2": ip2, "port2": port2,
        "name": player_name, "token": access_token,
    }

# ==================================================================
#  BOT SESSION  (per team, stop-able)
# ==================================================================
def _Session(host, port, state, uid, jwt, ts, key, iv, mode, tag, team_code, stop_event, barrier):
    s = None
    try:
        if stop_event.is_set():
            return
        s = socket.create_connection((host, int(port)), timeout=15)
        s.settimeout(20)
        _TuneSock(s)
        auth_hex = BuildAuthToken(uid, jwt, ts, key, iv, mode=mode)
        s.sendall(bytes.fromhex(auth_hex))
        state["ready"] = True
        state["online" if tag == "ChaT" else "online2"] = True

        print(f"[{tag}-{uid}] connected, waiting barrier (JOIN)")
        try:
            barrier.wait(timeout=20)
        except:
            pass
        if stop_event.is_set():
            return
        print(f"[{tag}-{uid}] barrier passed -> JOIN")

        join_pkt = Join_Team(team_code, key, iv)
        s.sendall(join_pkt)
        state["sent"] = state.get("sent", 0) + 1

        s.settimeout(1.0)
        target_uid = None; squad_code = None
        start = time.time()
        while time.time() - start < 15:
            if stop_event.is_set():
                return
            try:
                data = s.recv(65536)
                if not data:
                    break
                hex_data = data.hex()
                if hex_data.startswith('0500') and 100 < len(hex_data) < 5000:
                    try:
                        js = DeCode_PackEt(hex_data[10:])
                        if js:
                            packet = json.loads(js)
                            t_uid = packet.get('5', {}).get('data', {}).get('1', {}).get('data')
                            sq = packet.get('5', {}).get('data', {}).get('5', {}).get('data', {}).get('31', {}).get('data')
                            if not sq:
                                sq = packet.get('5', {}).get('data', {}).get('31', {}).get('data')
                            if t_uid and sq:
                                target_uid = t_uid; squad_code = sq
                                print(f"[{tag}-{uid}] target={target_uid} sq_len={len(str(squad_code))}")
                                break
                    except:
                        pass
            except socket.timeout:
                pass
            except:
                break

        if not target_uid or not squad_code:
            print(f"[{tag}-{uid}] no team data")
            try:
                barrier.wait(timeout=10)
            except:
                pass
            return

        try:
            s.close()
        except:
            pass
        if stop_event.is_set():
            return

        s = socket.create_connection((host, int(port)), timeout=15)
        s.settimeout(20)
        _TuneSock(s)
        s.sendall(bytes.fromhex(auth_hex))
        time.sleep(0.3)

        inv_pkt = SendInv(uid, target_uid, key, iv)
        s.sendall(inv_pkt)
        state["sent"] = state.get("sent", 0) + 1

        for _ in range(3):
            s.sendall(Join_Team(team_code, key, iv))
            time.sleep(0.02)

        print(f"[{tag}-{uid}] waiting barrier (GHOST)")
        try:
            barrier.wait(timeout=20)
        except:
            pass
        if stop_event.is_set():
            return
        print(f"[{tag}-{uid}] barrier passed -> GHOST")

        ghost_pkt = Send_GhosTs(int(target_uid), "[C][B][FF00FF]بوشي؁خي̶", squad_code, key, iv)
        for _ in range(3):
            if stop_event.is_set():
                break
            try:
                s.sendall(ghost_pkt)
                state["sent"] = state.get("sent", 0) + 1
            except:
                break
            time.sleep(0.01)
        print(f"[{tag}-{uid}] GHOST sent x3")

        try:
            barrier.wait(timeout=20)
        except:
            pass
        if stop_event.is_set():
            return

        exit_pkt = ExiT(key, iv)
        s.sendall(exit_pkt)
        state["sent"] = state.get("sent", 0) + 1
        print(f"[{tag}-{uid}] EXIT sent")

        time.sleep(0.3)
        return
    except Exception as e:
        print(f"[{tag}-{uid}] err: {e}")
        try:
            barrier.wait(timeout=5)
        except:
            pass
    finally:
        state["online" if tag == "ChaT" else "online2"] = False
        state["ready"] = False
        try:
            if s:
                s.close()
        except:
            pass

def _run_bot_loop(host, port, state, uid, jwt, ts, key, iv, mode, tag, team_code, stop_event, barrier):
    while not stop_event.is_set():
        try:
            _Session(host, port, state, uid, jwt, ts, key, iv, mode, tag, team_code, stop_event, barrier)
        except Exception as e:
            print(f"[{tag}-{uid}] loop err: {e}")
        if stop_event.is_set():
            break
        # sleep in small chunks so /stop responds fast
        for _ in range(10):
            if stop_event.is_set():
                break
            time.sleep(0.1)

# ==================================================================
#  TEAM CONTROL  (spam / stop)
# ==================================================================
def start_team(team_code):
    team_code = str(team_code).strip()
    if not team_code:
        return {"ok": False, "error": "empty team_code"}
    with TEAMS_LOCK:
        if team_code in TEAMS and TEAMS[team_code].get("running"):
            return {"ok": False, "error": f"team {team_code} already running"}

        # ensure sessions logged in
        with SESSIONS_LOCK:
            ready_sessions = [s for s in SESSIONS.values() if s.get("logged_in")]
        if not ready_sessions:
            return {"ok": False, "error": "no logged-in accounts available"}

        stop_event = threading.Event()
        barrier = threading.Barrier(len(ready_sessions) * 2)
        threads = []
        stats = {}

        for s in ready_sessions:
            uid = str(s["uid"])
            state = {"name": s["name"], "uid": uid, "token": s["token"],
                     "sent": 0, "online": False, "online2": False, "ready": False}
            stats[uid] = state
            t1 = threading.Thread(target=_run_bot_loop,
                                  args=(s["ip"], s["port"], state, s["uid"], s["jwt"], s["ts"], s["key"], s["iv"],
                                        "online", "ChaT", team_code, stop_event, barrier), daemon=True)
            t2 = threading.Thread(target=_run_bot_loop,
                                  args=(s["ip2"], s["port2"], state, s["uid"], s["jwt"], s["ts"], s["key"], s["iv"],
                                        "chat", "OnLinE", team_code, stop_event, barrier), daemon=True)
            threads.extend([t1, t2])

        TEAMS[team_code] = {
            "running": True, "stop_event": stop_event, "threads": threads,
            "stats": stats, "started_at": time.time(),
        }
        for t in threads:
            t.start()

        print(f"[TEAM {team_code}] started with {len(ready_sessions)} accounts")
        return {"ok": True, "team": team_code, "accounts": len(ready_sessions), "threads": len(threads)}

def stop_team(team_code):
    team_code = str(team_code).strip()
    with TEAMS_LOCK:
        team = TEAMS.get(team_code)
        if not team:
            return {"ok": False, "error": f"team {team_code} not found"}
        if not team.get("running"):
            return {"ok": False, "error": f"team {team_code} already stopped"}
        team["stop_event"].set()
        team["running"] = False
    print(f"[TEAM {team_code}] stop requested")
    return {"ok": True, "team": team_code, "status": "stopping"}

def team_status(team_code):
    with TEAMS_LOCK:
        team = TEAMS.get(team_code)
        if not team:
            return {"ok": False, "error": "not found"}
        stats = {uid: {"sent": st.get("sent", 0), "online": st.get("online", False),
                       "online2": st.get("online2", False)} for uid, st in team.get("stats", {}).items()}
        return {"ok": True, "team": team_code, "running": team.get("running", False),
                "uptime": int(time.time() - team.get("started_at", time.time())), "stats": stats}

# ==================================================================
#  FLASK API
# ==================================================================
@app.route("/", methods=["GET"])
def index():
    with TEAMS_LOCK:
        teams = {tc: {"running": t.get("running", False)} for tc, t in TEAMS.items()}
    with SESSIONS_LOCK:
        accs = [{"uid": str(s["uid"]), "name": s.get("name"), "logged_in": s.get("logged_in")} for s in SESSIONS.values()]
    return jsonify({"ok": True, "service": "VANTA BoT API", "accounts": accs, "teams": teams})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": int(time.time())})

@app.route("/login", methods=["GET", "POST"])
def api_login():
    """تسجيل الدخول لكل الحسابات المكوّنة في ACCOUNTS"""
    results = []
    for acc_uid, acc_pass in ACCOUNTS:
        try:
            res = login_account(acc_uid, acc_pass)
            if res:
                res["logged_in"] = True
                with SESSIONS_LOCK:
                    SESSIONS[str(res["uid"])] = res
                results.append({"uid": str(res["uid"]), "name": res.get("name"), "ok": True})
            else:
                results.append({"uid": acc_uid, "ok": False, "error": "login failed"})
        except Exception as e:
            results.append({"uid": acc_uid, "ok": False, "error": str(e)})
    return jsonify({"ok": True, "results": results})

@app.route("/spam", methods=["GET", "POST"])
def api_spam():
    """
    الاستخدام:
      /spam?team=123456789
      أو JSON body: {"team": "123456789"}
    """
    team_code = None
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        team_code = data.get("team") or data.get("team_code")
    if not team_code:
        team_code = request.args.get("team") or request.args.get("team_code")
    if not team_code:
        return jsonify({"ok": False, "error": "missing 'team' param"}), 400

    # auto-login if no sessions
    with SESSIONS_LOCK:
        have = any(s.get("logged_in") for s in SESSIONS.values())
    if not have:
        for acc_uid, acc_pass in ACCOUNTS:
            try:
                res = login_account(acc_uid, acc_pass)
                if res:
                    res["logged_in"] = True
                    with SESSIONS_LOCK:
                        SESSIONS[str(res["uid"])] = res
            except Exception as e:
                print(f"[auto-login {acc_uid}] {e}")

    return jsonify(start_team(team_code))

@app.route("/stop", methods=["GET", "POST"])
def api_stop():
    """
    الاستخدام:
      /stop?team=123456789
      أو JSON body: {"team": "123456789"}
    """
    team_code = None
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        team_code = data.get("team") or data.get("team_code")
    if not team_code:
        team_code = request.args.get("team") or request.args.get("team_code")
    if not team_code:
        return jsonify({"ok": False, "error": "missing 'team' param"}), 400
    return jsonify(stop_team(team_code))

@app.route("/status", methods=["GET"])
def api_status():
    team_code = request.args.get("team") or request.args.get("team_code")
    if not team_code:
        with TEAMS_LOCK:
            all_teams = {tc: {"running": t.get("running", False), "uptime": int(time.time() - t.get("started_at", time.time()))} for tc, t in TEAMS.items()}
        return jsonify({"ok": True, "teams": all_teams})
    return jsonify(team_status(team_code))

# ==================================================================
#  ENTRYPOINT
# ==================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)