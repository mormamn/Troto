#!/usr/bin/env python3

from databases import nvd


def main():
    nvd_handler = nvd.NVD()
    nvd_handler.get_db()
    nvd_handler.load()
    return


if __name__ == '__main__':
    main()
