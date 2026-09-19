#!/usr/bin/env python3
import secretstorage
import json
import sys

def main():
    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        items = collection.search_items({"service": "omarchy-totp"})
        
        result = {}
        for item in items:
            attrs = item.get_attributes()
            if "account" in attrs:
                result[attrs["account"]] = item.get_secret().decode("utf-8")
                
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"_error": str(e)}))

if __name__ == "__main__":
    main()
