import zlib
import gevent
import json
import traceback
from ..base import BaseSessionParser
from .structdef import c_ssh
from .state import SSHConnectionState


def choose_alg(alg_type, client_algs, server_algs):
    """Choose a common algorithm from the client & server lists
       This method returns the earliest algorithm on the client's
       list which is supported by the server.
    """

    for alg in client_algs:
        if alg in server_algs:
            # print alg_type, client_algs, server_algs, alg
            return alg

    raise Exception('No matching %s algorithm found' % alg_type)


class SshSessionParser(BaseSessionParser):
    def __init__(self, tcp_stream, output_dir, con_time, keyfile=None):
        super(SshSessionParser, self).__init__(tcp_stream, output_dir, con_time)
        self.keyfile = keyfile
        self.keys = []
        self.load_key_file()
        self.kex_alg = None
        self.enc_alg_cs = None
        self.enc_alg_sc = None
        self.mac_alg_cs = None
        self.mac_alg_sc = None
        self.cmp_alg_cs = None
        self.cmp_alg_sc = None
        self._recv_blocksize = 8
        self.client_state = SSHConnectionState(self.client_stream, True, self.log, self.keys)
        self.server_state = SSHConnectionState(self.server_stream, False, self.log, self.keys)

    def load_key_file(self):
        keyf = open(self.keyfile, "r")
        for line in keyf:
            key = json.loads(line)
            self.keys.append(key)

    def parse_protocol_version_exchange(self):
        self.client_state.recv_version()
        self.server_state.recv_version()

    def process_kex_init_exchange(self):
        self.log.protocol("[Key Exchange]")
        self.kex_alg = choose_alg("key exchange", self.client_state.kex.kex_algorithms, self.server_state.kex.kex_algorithms)
        enc_alg_cs = choose_alg('encryption', self.client_state.kex.encryption_algorithms_client_to_server, self.server_state.kex.encryption_algorithms_client_to_server)
        enc_alg_sc = choose_alg('encryption', self.client_state.kex.encryption_algorithms_server_to_client, self.server_state.kex.encryption_algorithms_server_to_client)
        mac_alg_cs = choose_alg('MAC', self.client_state.kex.mac_algorithms_client_to_server, self.server_state.kex.mac_algorithms_client_to_server)
        mac_alg_sc = choose_alg('MAC', self.client_state.kex.mac_algorithms_server_to_client, self.server_state.kex.mac_algorithms_server_to_client)
        cmp_alg_cs = choose_alg('compression', self.client_state.kex.compression_algorithms_client_to_server, self.server_state.kex.compression_algorithms_client_to_server)
        cmp_alg_sc = choose_alg('compression', self.client_state.kex.compression_algorithms_server_to_client, self.server_state.kex.compression_algorithms_server_to_client)

        self.client_state.enc_algo_cs = self.server_state.enc_algo_cs = enc_alg_cs
        self.client_state.enc_algo_sc = self.server_state.enc_algo_sc = enc_alg_sc

        self.client_state.mac_alg_cs = self.server_state.mac_alg_cs = mac_alg_cs
        self.client_state.mac_alg_sc = self.server_state.mac_alg_sc = mac_alg_sc

        self.client_state.cmp_alg_cs = self.server_state.cmp_alg_cs = cmp_alg_cs
        self.client_state.cmp_alg_sc = self.server_state.cmp_alg_sc = cmp_alg_sc

        self.log.protocol("Chosen kex alg: {}".format(self.kex_alg))
        self.log.protocol("Chosen enc alg c-s: {}, s-c: {}".format(enc_alg_cs, enc_alg_sc))
        self.log.protocol("Chosen MAC alg c-s: {}, s-c: {}".format(mac_alg_cs, mac_alg_sc))
        self.log.protocol("Chosen compression alg c-s: {}, s-c: {}".format(cmp_alg_cs, cmp_alg_sc))

    def next_session_frame(self):
        # Determine where in the session we are and if the upcoming packet is server or client. Then read a SSH frame from that stream.
        off = self.session_offset
        metadata = self.session_metadata.get(off)
        # print off - metadata.offset, metadata.length
        if metadata is not None:
            session_state = self.client_state if metadata.is_client else self.server_state
            frame = session_state.recv_frame()
            # print off, metadata
            return metadata.is_client, frame[0], frame[1]
        return None

    def process_userauth_success(self):
        self.server_state.auth_complete = True
        self.client_state.auth_complete = True

    def process_frame(self, is_client, frame_type, frame_data):
        stream_state = self.client_state if is_client else self.server_state
        stream_state.process_frame(frame_type, frame_data)
        if frame_type == c_ssh.MsgType.SSH_MSG_KEXINIT:
            if self.server_state.kex_ongoing and self.client_state.kex_ongoing:
                self.process_kex_init_exchange()
        elif frame_type == c_ssh.MsgType.SSH_MSG_USERAUTH_SUCCESS:
            self.process_userauth_success()
        elif frame_type == c_ssh.MsgType.SSH_MSG_NEWKEYS:
            stream_id = 'client' if is_client else 'server'
            next_packet_metadata = self.get_next_packet_metadata(stream=stream_id)
            stream_state.load_decryption_key(next_packet_metadata)

    def _parse(self):
        self.parse_protocol_version_exchange()
        while True:
            frame_info = None
            try:
                frame_info = self.next_session_frame()
                if frame_info is not None:
                    is_client, frame_type, frame_data = frame_info
                    self.process_frame(is_client, frame_type, frame_data)
                else:
                    if self.done:
                        break
            except Exception as e:
                tb = traceback.format_exc()
                self.log.error("Exception when processing frame: {}. Exception: {}\n{}".format(frame_info, e, tb))
                self.aborted_parsing = True
                return
            gevent.sleep(0)
