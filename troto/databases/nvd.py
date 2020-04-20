import os
import json
import shutil

from datetime import datetime
from troto.databases import utils


class NVD():
    BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
    DB_PATH = "./nvd-db"

    def __init__(self, min_year=2019, output=None):
        self.years = [y for y in range(min_year, datetime.now().year + 1)]
        if output:
            self.output_file = output
        else:
            self.output_file = f"{self.DB_PATH}/NVD-Kube-CVE.json"
        self.preflight()

    def preflight(self):
        if not os.path.exists(self.DB_PATH):
            os.makedirs(self.DB_PATH)
            print(f"Created folder: {self.DB_PATH}")
        else:
            for filename in os.listdir(self.DB_PATH):
                file_path = os.path.join(self.DB_PATH, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                        print(f"Deleted file {file_path}")
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        print(f"Deleted folder {file_path}")
                except Exception as e:
                    print(f"Failed to delete {file_path}. Reason: {e}")

    def get_sha256(self, year):
        meta_file = f"nvdcve-1.1-{year}.meta"
        url = f"{self.BASE_URL}/{meta_file}"
        utils.download(url, path=f"./tmp{year}.meta")
        return None

    def get_db(self):
        print(f"Getting DB's from NVD for the years {self.years}")
        for y in self.years:
            file_name = f"nvdcve-1.1-{y}.json.gz"
            url = f"{self.BASE_URL}/{file_name}"
            utils.download(url, path=f"{self.DB_PATH}/{file_name}")
            utils.extract(f"{self.DB_PATH}/{file_name}", f"{self.DB_PATH}/nvd-{y}.json")
            print(f"Downloaded and extracted db for {y}")

    def scan_db(self):
        files = list()
        for db in os.listdir(f"{self.DB_PATH}"):
            if db.endswith(".json"):
                files.append(os.path.join(f"{self.DB_PATH}/{db}"))
        return files

    def load_db(self):
        db_dump = []
        db_files = self.scan_db()
        for p in db_files:
            with open(p) as jf:
                data = json.load(jf)
                for v in data['CVE_Items']:
                    try:
                        if "REJECT" not in v['cve']['description']['description_data'][0]['value']:
                            for node in v['configurations']['nodes']:
                                for cpe in node['cpe_match']:
                                    if "kubernetes" in cpe['cpe23Uri']:
                                        t = utils.template(id=v['cve']['CVE_data_meta']['ID'],
                                                           desc=v['cve']['description']['description_data'][0]['value'],
                                                           cvssV2=v['impact']['baseMetricV2']['cvssV2']['baseScore'],
                                                           cvssV3=v['impact']['baseMetricV3']['cvssV3']['baseScore'],
                                                           components=cpe)
                                        db_dump.append(t)
                                        break
                    except KeyError:
                        continue
        return json.dumps(db_dump, indent=4)

    def export_db(self):
        print(f"Exporting db to file {self.output_file}")
        utils.save_file(self.output_file, input=self.load_db())
