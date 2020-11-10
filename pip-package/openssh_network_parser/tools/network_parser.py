#!/usr/bin/env python
from gevent.monkey import patch_all
patch_all()
import argparse
import pwd
import os
import logging
import resource

from datetime import datetime
from openssh_network_parser import NetworkParser, get_unused_filepath
from openssh_network_parser.utils import add_logging_level

LOGGING_LEVEL_PROTOCOL = 9
LOGGING_LEVEL_PROTOCOLV = 8
LOGGING_LEVEL_NETWORK = 7


def print_file_limit():
    print "getrlimit:", resource.getrlimit(resource.RLIMIT_NOFILE)


def configure_file_limit(limit):
    print_file_limit()
    resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    print_file_limit()


def drop_priv(user):
    pwnam = pwd.getpwnam(user)
    os.setgid(pwnam.pw_gid)
    os.setuid(pwnam.pw_uid)


def valid_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


class kvdictAppendAction(argparse.Action):
    """
    argparse action to split an argument into KEY=VALUE form
    on the first = and append to a dictionary.
    """
    def __call__(self, parser, args, values, option_string=None):
        assert(len(values) == 1)
        try:
            (k, v) = values[0].split("=", 2)
        except ValueError as ex:
            raise argparse.ArgumentError(self, r"could not parse argument \"{values[0]}\" as k=v format")
        d = getattr(args, self.dest) or {}
        d[k] = v
        setattr(args, self.dest, d)


def main():
    add_logging_level("PROTOCOL", LOGGING_LEVEL_PROTOCOL, "protocol")
    add_logging_level("PROTOCOLV", LOGGING_LEVEL_PROTOCOLV, "protocolv")
    add_logging_level("NETWORK", LOGGING_LEVEL_NETWORK, "network")

    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=help_formatter)
    parser.add_argument("-p", "--pcap", help="Pcap file to parse", required=True)
    parser.add_argument("-o", "--output", help="Output dir", required=True)
    parser.add_argument("--dport", help="The dest port to filter on", default=None, type=int)
    parser.add_argument("--sport", help="The src port to filter on", default=None, type=int)
    parser.add_argument("--src", help="The src to filter on", default=None, type=str)
    parser.add_argument("--dst", help="The dst to filter on", default=None, type=str)
    parser.add_argument("-s", "--stdout", help="Print to stdout instead of log files", default=False, action='store_true')
    parser.add_argument("-u", "--user", help="Drop privs to user", type=str)
    parser.add_argument("--stats", help="Write stats to specified file", type=str, default=None)
    parser.add_argument("-f", "--file_limit", help="Set file descriptor limit", type=int)
    parser.add_argument("--startdate", help="The Start Date - format YYYY-MM-DD", required=False, default=None, type=valid_date)
    parser.add_argument("--proto", help="Protocol to parse", required=True, type=str)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--popt", nargs=1, action=kvdictAppendAction, metavar="KEY=VALUE", help="Protocol parser key/value options.")
    args = parser.parse_args()

    levels = [logging.INFO, logging.DEBUG, LOGGING_LEVEL_PROTOCOL, LOGGING_LEVEL_PROTOCOLV, LOGGING_LEVEL_NETWORK]
    level = levels[min(len(levels), args.verbose)]

    if args.file_limit is not None:
        configure_file_limit(args.file_limit)
    else:
        print_file_limit()

    if args.user:
        drop_priv(args.user)

    stats_file = args.stats
    if stats_file is not None:
        stats_file = get_unused_filepath(stats_file)

    proto_ops = args.popt or dict()

    parser = NetworkParser(
        args.proto,
        proto_ops,
        args.pcap,
        args.output,
        level,
        args.stdout,
        stats_file=stats_file,
        dst=args.dst,
        dest_port=args.dport,
        src=args.src,
        src_port=args.sport,
        start_date=args.startdate
    )
    parser.run()


if __name__ == "__main__":
    main()