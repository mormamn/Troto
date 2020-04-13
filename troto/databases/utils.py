import os
import urllib3
import shutil
import hashlib
import gzip

BUF_SIZE = 65536  # 64kb chunks


def download(url, path):
    c = urllib3.PoolManager()
    with c.request('GET', url, preload_content=False) as resp, open(path, 'wb') as out_file:
        shutil.copyfileobj(resp, out_file)
    resp.release_conn()


def get_hash(path):
    md5 = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def secure_download(url, path, md5):
    download(url, path)
    return get_hash(path) == md5


def extract(path, outout):
    with gzip.open(path, 'rb') as f_in:
        with open(outout, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


def save_file(path, input):
    if os.path.exists(path):
        print(f"File already exist at path: {path}")
    else:
        with open(path, 'w') as of:
            of.write(input)
