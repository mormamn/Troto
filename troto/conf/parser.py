from argparse import ArgumentParser
from datetime import datetime


def parse():
    parser = ArgumentParser(description="Troto - find various of Kubernetes CVE's from different sources")

    parser.add_argument("--source", type=str, default="nvd", metavar="SOURCE", help="Set a source to search in")

    parser.add_argument("--start-year",
                        type=int,
                        default=2018,
                        help="Set a start year, CVE before that year will not apear")

    args = parser.parse_args()

    if args.start_year < 2002 or args.start_year > datetime.now().year:
        parser.error("Start year can't be lower than 2002 or higer than the current year")
    else:
        return args
