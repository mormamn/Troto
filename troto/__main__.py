#!/usr/bin/env python3

from troto.databases import nvd
from troto.conf import config


def main():
    nvd_handler = nvd.NVD(min_year=config.start_year, output=config.output)
    nvd_handler.get_db()
    nvd_handler.export_db()


if __name__ == '__main__':
    main()
