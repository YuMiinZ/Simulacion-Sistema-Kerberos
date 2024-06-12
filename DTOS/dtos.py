import json, base64
from datetime import datetime

def bytes_to_string_base64(bytes:bytes) -> str:
    bytes_base64 = base64.b64encode(bytes)
    return bytes_base64.decode('utf-8')

def string_base64_to_bytes(string:str) -> bytes:
    return base64.b64decode(string.encode('utf-8'))

def custom_encoder(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

class Error:
    def __init__(self, error:str):
        self.error = error

    def to_json(self):
        return json.dumps({
            "error": self.error
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["error"])

class Msg_A:
    def __init__(self, client_tgs_key : bytes):
        self.client_tgs_key = client_tgs_key

    def to_json(self):
        return json.dumps({
            "client_tgs_key": bytes_to_string_base64(self.client_tgs_key)
        })
    
    def to_bytes(self):
        return self.to_json().encode()

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["client_tgs_key"]))

class Msg_B:
    def __init__(self, client_tgs_key:bytes, client_id:int, address:any, ttl:datetime):
        self.client_tgs_key = client_tgs_key
        self.client_id = client_id
        self.address = address
        self.ttl = ttl

    def to_json(self):
        return json.dumps({
            "client_tgs_key": bytes_to_string_base64(self.client_tgs_key),
            "client_id": self.client_id,
            "address": self.address,
            "ttl": self.ttl
        }, default=custom_encoder)

    def to_bytes(self):
        return self.to_json().encode()
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["client_tgs_key"]), data["client_id"], data["address"], data["ttl"])
    

class AS_To_Client:
    def __init__(self, msg_a:bytes, msg_b:bytes):
        self.msg_a = msg_a
        self.msg_b = msg_b
        self.error = ""

    def to_json(self):
        return json.dumps({
            "msg_a": bytes_to_string_base64(self.msg_a),
            "msg_b": bytes_to_string_base64(self.msg_b),
            "error": self.error
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["msg_a"]), string_base64_to_bytes(data["msg_b"]), data["error"])

class Client_To_AS:
    def __init__(self, user_id):
        self.user_id = user_id
        self.source = "client"

    def to_json(self) -> str:
        return json.dumps({
            "user_id": self.user_id,
            "source": self.source
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["user_id"], data["source"])

class MsgC:
    def __init__(self, service : str, msgB : bytes):
        self.service = service
        self.msg_b = bytes

    def to_json(self):
        return json.dumps({
            "service": self.service,
            "msgB": bytes_to_string_base64(self.msg_b)
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["service"]), data["msgB"])

class MsgD: 
    def __init__(self, client_id:int, ttl:datetime):
        self.client_id = client_id
        self.ttl = ttl

    def to_json(self):
        return json.dumps({
            "client_id": self.client_id,
            "ttl": self.ttl
        }, default=custom_encoder)
    
    def to_bytes(self):
        return self.to_json().encode()

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["client_id"],data["ttl"])    

class Client_To_TGS:
    def __init__(self, msg_c : MsgC, msg_d: bytes):
        self.msg_c = msg_c
        self.msg_d = msg_d
        self.source = "client"

    def to_json(self):
        return json.dumps({
            "msg_c": self.msg_c,
            "msg_d": bytes_to_string_base64(self.msg_d),
            "source": self.source,
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["msg_c"], string_base64_to_bytes(data["msg_d"]), data["source"])
    
class Msg_E: # Client-to-server ticket
    def __init__(self, client_server_key:bytes, client_id:int, address:any, ttl:datetime):
        self.client_server_key = client_server_key
        self.client_id = client_id
        self.address = address
        self.ttl = ttl

    def to_json(self):
        return json.dumps({
            "client_server_key": bytes_to_string_base64(self.client_server_key),
            "client_id": self.client_id,
            "address": self.address,
            "ttl": self.ttl
        }, default=custom_encoder)
    
    def toBytes(self):
        return self.to_json().encode()

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["client_server_key"]), data["client_id"], data["address"], data["ttl"])
    
class Msg_F:
    def __init__(self, client_server_key:bytes):
        self.client_server_key = client_server_key

    def to_json(self):
        return json.dumps({
            "client_server_key": bytes_to_string_base64(self.client_server_key)
        })
    
    def toBytes(self):
        return self.to_json().encode()
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["client_server_key"]))
    
class TGS_To_Client:
    def __init__(self, msg_e:bytes, msg_f:bytes):
        self.msg_e = msg_e
        self.msg_f = msg_f
        self.error = ""

    def to_json(self):
        return json.dumps({
            "msg_e": bytes_to_string_base64(self.msg_e),
            "msg_f": bytes_to_string_base64(self.msg_f),
            "error": self.error
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["msg_e"]), string_base64_to_bytes(data["msg_f"]), data["error"])
    

class Msg_G:
    def __init__(self, client_id:int, ttl:datetime):
        self.client_id = client_id
        self.ttl = ttl

    def to_json(self):
        return json.dumps({
            "client_id": self.client_id,
            "ttl": self.ttl
        }, default=custom_encoder)
    
    def to_bytes(self):
        return self.to_json().encode()

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["client_id"],data["ttl"])    
    

class Client_To_Server:
    def __init__(self, msg_e: bytes, msg_g: bytes):
        self.msg_e = msg_e
        self.msg_g = msg_g
        self.source = "client"

    def to_json(self):
        return json.dumps({
            "msg_e": bytes_to_string_base64(self.msg_e),
            "msg_g": bytes_to_string_base64(self.msg_g),
            "source": self.source
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["msg_e"]), string_base64_to_bytes(data["msg_g"]), data["source"])
    

class Msg_H:
    def __init__ (self, ttl):
        self.ttl = ttl

    def to_json(self):
        return json.dumps({
            "ttl": self.ttl
        }, default=custom_encoder)
    
    def to_bytes(self):
        return self.to_json().encode()
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(data["ttl"])
    

class SS_To_Client:
    def __init__(self, msg_h:bytes):
        self.msg_h = msg_h
        self.error = ""

    def to_json(self):
        return json.dumps({
            "msg_h": bytes_to_string_base64(self.msg_h),
            "error": self.error
        })

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(string_base64_to_bytes(data["msg_h"]), data["error"])
    