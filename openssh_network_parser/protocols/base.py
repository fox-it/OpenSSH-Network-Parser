import tempfile
import os
import gevent
from gevent.fileobject import FileObject
import logging
from gevent.lock import BoundedSemaphore
from datetime import datetime
from ..utils import filesize, get_unused_filepath, util_repr
from ..rangemap import RangeLookupTable


IO_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB


class StreamMetaData(object):
    def __init__(self, offset, length, ts, is_client):
        self.offset = offset
        self.length = length
        self.ts = ts
        self.is_client = is_client

    @property
    def timestamp(self):
        return datetime.utcfromtimestamp(self.ts)

    def __str__(self):
        return util_repr(self)


class TcpStream(object):
    def __init__(self, log, id_str):
        self.id_str = id_str
        self.log = log
        spooled_temp_file = tempfile.SpooledTemporaryFile(bufsize=IO_BUFFER_SIZE)
        self.stream = spooled_temp_file
        self.closed = False

    @property
    def size(self):
        return filesize(self.stream)

    @property
    def data_available(self):
        return self.offset - self.size

    @property
    def offset(self):
        return self.stream.tell()

    def reset(self):
        self.log.network("reset")
        self.stream.seek(0)

    def read(self, length=None):
        self.log.network("{} R {} {}".format(self.id_str, self.offset, length))
        data = self.stream.read(length)
        self.log.network("< {}".format(len(data)))
        return data

    def readline(self):
        self.log.network("{} RL {}".format(self.id_str, self.offset))
        data = self.stream.readline()
        self.log.network("< {}".format(len(data)))
        return data

    def peek(self, length):
        off = self.offset
        data = self.read(length)
        self.stream.seek(off)
        return data

    def write(self, data):
        if self.closed:
            raise Exception("Closed MF!")
        data_len = len(data)
        self.log.network("{} W {} {}".format(self.id_str, self.offset, data_len))
        self.stream.write(data)
        #self.flush()
        # print '< write'

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()


class BaseSessionParser(object):
    def __init__(self, tcp_stream, output_dir, con_time):
        self.connection_time = con_time
        self.connection_end_time = None
        self.output_dir = output_dir
        self.tcp_stream = tcp_stream
        self.worker = None
        self.done = False

        (src, src_port), (dst, dst_port) = self.tcp_stream.addr
        self.src = src
        self.src_port = src_port
        self.dst = dst
        self.dst_port = dst_port

        self.work_dir = os.path.join(self.output_dir, src)
        if not os.path.exists(self.work_dir):
            os.makedirs(self.work_dir)

        self.log_name = "openssh_network_parser.stream.{}:{}-{}:{}-{}".format(self.src, self.src_port, self.dst, self.dst_port, self.connection_time)
        self.log = logging.getLogger(self.log_name)

        self.session_metadata = RangeLookupTable()
        self.client_stream = TcpStream(self.log, "<-")
        self.server_stream = TcpStream(self.log, "->")
        self.aborted_parsing = False

    @property
    def session_offset(self):
        return self.client_stream.offset + self.server_stream.offset

    @property
    def hdr(self):
        return "{}:{} -> {}:{}\t{} - {}".format(self.src, self.src_port, self.dst, self.dst_port, self.connection_time, self.connection_end_time)

    def cleanup(self):
        if self.client_stream is not None:
            self.client_stream.close()
        if self.server_stream is not None:
            self.server_stream.close()
        self.log = None
        self.client_stream = None
        self.server_stream = None

    def create_local_file(self, filename, subfolder=None):
        subfolder = subfolder or ""
        local_file_path = os.path.join(self.work_dir, "files", subfolder, filename)
        local_file_path = get_unused_filepath(local_file_path)
        local_file = open(local_file_path, "wb")

        global_file_path = os.path.join(self.output_dir, "files", subfolder, filename)
        global_file_path = get_unused_filepath(global_file_path)
        os.symlink(local_file_path, global_file_path)
        return local_file_path, local_file

    @property
    def remaining_client_data(self):
        return self.client_stream.data_available

    @property
    def remaining_server_data(self):
        return self.server_stream.data_available

    @property
    def server_file_size(self):
        return self.server_stream.size

    @property
    def client_file_size(self):
        return self.client_stream.size

    def write_client(self, data, ts):
        if self.aborted_parsing:
            self.log.warn("Ignoring client data in stream, parsing aborted!")
            return
        session_offset = self.session_offset
        data_len = len(data)

        metadata = StreamMetaData(session_offset, data_len, ts, False)
        # self.log.network("-> W {} {}".format(session_offset, data_len))
        self.session_metadata.append(session_offset + data_len -1, metadata)
        self.server_stream.write(data)
        gevent.sleep(0)

    def write_server(self, data, ts):
        if self.aborted_parsing:
            self.log.warn("Ignoring server data in stream, parsing aborted!")
            return
        session_offset = self.session_offset
        data_len = len(data)
        # self.log.network("<- W {} {}".format(session_offset, data_len))
        metadata = StreamMetaData(session_offset, data_len, ts, True)
        self.session_metadata.append(session_offset + data_len - 1, metadata)
        self.client_stream.write(data)
        gevent.sleep(0)

    def get_next_packet_metadata(self, stream=None):
        off = self.session_offset
        if stream is not None:
            stream_is_client = stream == 'client'
            while True:
                metadata = self.session_metadata.get(off)
                if metadata is None:
                    return None
                if metadata.is_client == stream_is_client:
                    return metadata
                off += metadata.length

        metadata = self.session_metadata.get(off)
        return metadata

    def _parse(self):
        while True:
            off = self.session_offset
            metadata = self.session_metadata.get(off)
            # print off, metadata
            # print '> _parse'
            if metadata is not None:
                direction_str = "->" if metadata.is_client else "<-"
                self.log.info("{} {}\t{}".format(direction_str, metadata.length, metadata.timestamp))
                if metadata.is_client:
                    # print "read_client {}".format(metadata.length)
                    self.client_stream.read(metadata.length)
                else:
                    self.server_stream.read(metadata.length)
            else:
                if self.done:
                    break
            # print '< _parse'
            gevent.sleep(0)

    def parse(self):
        hdr = self.hdr
        self.log.info("[{}]".format(hdr))
        self.client_stream.flush()
        self.server_stream.flush()
        self.client_stream.reset()
        self.server_stream.reset()
        self._parse()

    def finish(self):
        self.done = True
        #gevent.joinall([self.worker])
