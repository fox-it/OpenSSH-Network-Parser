#!/usr/bin/env python
import gevent
import gevent.monkey
gevent.monkey.patch_all()
import logging
import sys
import os
import nids
import traceback
import urlparse
import importlib
from datetime import datetime
from utils import get_unused_filepath


end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)


class StatsRecord(object):
    def __init__(self, src):
        self.src = src
        self.total_client = 0
        self.total_server = 0
        self.unparsed_client = 0
        self.unparsed_server = 0
        self.total_connections = 0

    @property
    def total(self):
        return self.total_server + self.total_client


def format_stats_row(stats_entry):
    values = [stats_entry.total_connections, stats_entry.total_server, stats_entry.total_client, stats_entry.total, stats_entry.unparsed_server, stats_entry.unparsed_client]
    result = stats_entry.src.ljust(25)
    for value in values:
        if not isinstance(value, str):
            value = str(value)
        result += value.ljust(20)
    return result


def output_stats(stats_file, stats):
    file_hdr = "IP".ljust(25) + "Total Conn".ljust(20) + "Total Server".ljust(20) + "Total Client".ljust(
        20) + "Total".ljust(20) + "Remaining Server".ljust(20) + "Remaining Client".ljust(20)
    stats_file.write(file_hdr + "\n")
    stats_list = stats.values()
    stats_list.sort(key=lambda x: x.total, reverse=True)
    for stats_entry in stats_list:
        file_entry = format_stats_row(stats_entry)
        stats_file.write(file_entry + "\n")
    stats_file.flush()


def parser_adapter(proto, proto_opts, tcp_stream, output_dir, con_time):
    mod = importlib.import_module("openssh_network_parser.protocols.{}".format(proto))
    clsname = "{}SessionParser".format(proto.title())
    cls = getattr(mod, clsname)
    return cls(tcp_stream, output_dir, con_time, **proto_opts)


class NetworkParser(object):
    def __init__(self,
                 protocol_uri,
                 protocol_opts,
                 pcap_filepath,
                 output_dir,
                 log_level,
                 log_to_stdout,
                 stats_file=None,
                 dst=None,
                 dest_port=None,
                 src=None,
                 src_port=None,
                 start_date=None,
                 ):
        self._log_to_stdout = log_to_stdout
        self._log_level = log_level
        self._proto_uri = protocol_uri
        self._proto_opts = protocol_opts
        self._dest_port = dest_port
        self._src_port = src_port
        self._src = src
        self._dst = dst
        self.output_dir = output_dir
        self._pcap_filepath = pcap_filepath
        self._start_date = start_date
        nids.param("scan_num_hosts", 0)  # disable portscan detection
        nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming
        nids.param("filename", pcap_filepath)
        self.stream_parsers = {}
        self.stats = {}
        if stats_file is None:
            now = datetime.utcnow()
            formatted_time = now.strftime("%Y-%m-%d--%H-%M-%S")
            self.stats_file_path = os.path.join(self.output_dir, "stats_{}.txt".format(formatted_time))
        else:
            self.stats_file_path = stats_file

    def record_stats(self, stream_parser):
        current_server = stream_parser.server_stream.offset
        current_client = stream_parser.client_stream.offset
        remaining_server = stream_parser.remaining_server_data
        remaining_client = stream_parser.remaining_client_data
        stream_parser.log.info("Server stream offset: 0x{:x}".format(current_server))
        stream_parser.log.info("Client stream offset: 0x{:x}".format(current_client))
        stream_parser.log.info("Remaining server data: 0x{:x}".format(remaining_server))
        stream_parser.log.info("Remaining client data: 0x{:x}".format(remaining_client))

        entry = self.stats.get(stream_parser.src, StatsRecord(stream_parser.src))
        entry.total_connections += 1
        entry.total_client += stream_parser.client_file_size
        entry.total_server += stream_parser.server_file_size
        entry.unparsed_client += remaining_client
        entry.unparsed_server += remaining_server
        self.stats[stream_parser.src] = entry

    def configure_stream_logging(self, stream_parser):
        formatter = logging.Formatter('%(message)s')
        if self._log_to_stdout:
            handler = logging.StreamHandler()
        else:
            formatted_time = stream_parser.connection_time.strftime("%Y-%m-%d--%H-%M-%S")
            log_filename = "{}.txt".format(formatted_time)
            log_filepath = os.path.join(stream_parser.work_dir, log_filename)
            log_filepath = get_unused_filepath(log_filepath)
            handler = logging.FileHandler(log_filepath)

        stream_parser.log.setLevel(self._log_level)
        handler.setLevel(self._log_level)
        handler.setFormatter(formatter)
        stream_parser.log.addHandler(handler)

    def handle_tcp_stream_wrapper(self, tcp_stream):
        stream_parser = self.stream_parsers.get(tcp_stream.addr, None)
        try:
            self.handle_tcp_stream(tcp_stream)
        except Exception as e:
            tb = traceback.format_exc()
            print >>sys.stderr, "Exception in handle_tcp_stream: {}\n{}".format(e, tb)
            if stream_parser is not None:
                stream_parser.log.error("Exception: {}\n{}".format(e, tb))

    def handle_tcp_stream(self, tcp_stream):
        # print tcp_stream.addr, tcp_stream.nids_state, (nids.NIDS_JUST_EST, nids.NIDS_DATA, end_states)
        if tcp_stream.nids_state == nids.NIDS_JUST_EST:
            # new to us, but do we care?
            ((src, sport), (dst, dport)) = tcp_stream.addr

            if self._dst is not None and dst != self._dst:
                return
            if self._dest_port is not None and dport != self._dest_port:
                return
            if self._src is not None and src != self._src:
                return
            if self._src_port is not None and sport != self._src_port:
                return
            dt = datetime.utcfromtimestamp(nids.get_pkt_ts())
            if self._start_date is not None and dt < self._start_date:
                return

            tcp_stream.client.collect = 1
            tcp_stream.server.collect = 1

            if tcp_stream.addr in self.stream_parsers:
                raise Exception("Addr already known in streams?!")

            stream_parser = parser_adapter(self._proto_uri, self._proto_opts, tcp_stream, self.output_dir, dt)
            self.configure_stream_logging(stream_parser)

            if stream_parser is None:
                raise Exception("Unknown proto '{}'".format(self._proto_uri))
            self.stream_parsers[tcp_stream.addr] = stream_parser

        elif tcp_stream.nids_state == nids.NIDS_DATA:
            client_stream = tcp_stream.client
            server_stream = tcp_stream.server

            ts = nids.get_pkt_ts()
            stream_parser = self.stream_parsers[tcp_stream.addr]
            if client_stream.count_new > 0:
                stream_parser.write_client(client_stream.data[:client_stream.count_new], ts)
            if server_stream.count_new > 0:
                stream_parser.write_server(server_stream.data[:server_stream.count_new], ts)
            stream_parser.last_packet_ts = ts

        elif tcp_stream.nids_state in end_states:
            stream_parser = self.stream_parsers[tcp_stream.addr]
            dt = datetime.utcfromtimestamp(nids.get_pkt_ts())
            gevent.spawn(self.finish_complete_stream, stream_parser, dt)
            del self.stream_parsers[tcp_stream.addr]

    def finish_complete_stream(self, stream_parser, end_datetime):
        stream_parser.connection_end_time = end_datetime
        try:
            stream_parser.finish()
            stream_parser.parse()
        except Exception as e:
            tb = traceback.format_exc()
            stream_parser.log.error(stream_parser.hdr)
            stream_parser.log.error(e)
            stream_parser.log.error(tb)
            if not isinstance(e, (EOFError, )):
                print >>sys.stderr, stream_parser.hdr
                print >>sys.stderr, str(e)
                print >>sys.stderr, traceback.print_exc()
        finally:
            self.record_stats(stream_parser)
            stream_parser.cleanup()

    def save_stats(self):
        stats_file = open(self.stats_file_path, "w")
        output_stats(stats_file, self.stats)
        stats_file.close()

    def finish(self):
        # parse remaining streams that are not in END state
        stream_copy = self.stream_parsers.copy()
        for stream_addr in stream_copy:
            stream_parser = self.stream_parsers[stream_addr]
            dt = datetime.utcfromtimestamp(stream_parser.last_packet_ts)
            stream_parser.log.warning("Warning: stream not in closed state!")
            self.finish_complete_stream(stream_parser, dt)
            del self.stream_parsers[stream_addr]

    def run(self):
        files_dir = os.path.join(self.output_dir, "files")
        if not os.path.exists(files_dir):
            os.mkdir(files_dir)

        nids.init()
        nids.register_tcp(self.handle_tcp_stream_wrapper)
        try:
            nids.run()
            self.finish()
            self.save_stats()
        except nids.error, e:
            print >>sys.stderr, "nids/pcap error:", e
        except Exception, e:
            tb = traceback.format_exc()
            print >>sys.stderr, "misc. exception (runtime error in user callback?):", e, tb
        gevent.wait()
