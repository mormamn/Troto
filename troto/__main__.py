#!/usr/bin/env python3

from troto.databases import nvd


def main():
    nvd_handler = nvd.NVD()
    nvd_handler.get_db()
    print(nvd_handler.load())


if __name__ == '__main__':
    main()
