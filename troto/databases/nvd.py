import os

import ijson
from databases import utils
from datetime import datetime


class NVD():
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
    DB_PATH = "./nvd-db"

    def __init__(self, min_year=2019):
        self.years = [y for y in range(min_year, datetime.now().year + 1)]
        self.preflight()

    def preflight(self):
        if not os.path.exists(self.DB_PATH):
            os.makedirs(self.DB_PATH)
            print(f"Created folder: {self.DB_PATH}")

    def get_sha256(self, year):
        meta_file = f"nvdcve-1.1-{year}.meta"
        url = f"{self.BASE_URL}/{meta_file}"
        utils.download(url, path=f"./tmp{year}.meta")
        return None

    def get_db(self):
        for y in self.years:
            file_name = f"nvdcve-1.1-{y}.json.gz"
            url = f"{self.BASE_URL}/{file_name}"
            utils.download(url, path=f"{self.DB_PATH}/{file_name}")
            utils.extract(f"{self.DB_PATH}/{file_name}", f"{self.DB_PATH}/nvd-{y}.json")
            print(f"Downloaded and extracted db for {y}")

    def load(self):
        data = ijson.parse(open(f"{self.DB_PATH}/nvd-2020.json"))
        for key, type, value in data:
            if type == "string" and "kubernetes" in value:
                print(f"{key}   {type}   {value}")
        return
