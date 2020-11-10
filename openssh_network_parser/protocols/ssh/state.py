import dissect.cstruct
from .structdef import c_ssh
from .crypto.encryption import get_encryption_params, get_encryption
from .compression import get_compression_params, get_decompressor
from cStringIO import StringIO
from openssh_network_parser.utils import pretty_format_struct
from .crypto.utils import to_bytes, int64_from_bytes


def pretty_format_struct_ex(struct):
    def callback(val):
        if isinstance(val, dissect.cstruct.Instance):
            if val._type.name == "NameList":
                return val.strlist
            elif val._type.name == "String":
                return val.data
        return val
    return pretty_format_struct(struct, exclude_fields=["msg_type"], value_callback=callback)


def namelist_to_arr(nl):
    if nl.length > 0:
        return nl.strlist.split(",")
    return []


def determine_ssh_msg_type(data):
    msg_type_raw = c_ssh.uint8(data, len(c_ssh.MsgType))
    msg_type = c_ssh.MsgType(msg_type_raw)
    return msg_type


class Kex(object):
    def __init__(self, kex_struct):
        self.kex_struct = kex_struct

    def pretty_str(self):
        return pretty_format_struct_ex(self.kex_struct)

    @property
    def encryption_algorithms_client_to_server(self):
        return namelist_to_arr(self.kex_struct.encryption_algorithms_client_to_server)

    @property
    def encryption_algorithms_server_to_client(self):
        return namelist_to_arr(self.kex_struct.encryption_algorithms_server_to_client)

    @property
    def kex_algorithms(self):
        return namelist_to_arr(self.kex_struct.kex_algorithms)

    @property
    def mac_algorithms_client_to_server(self):
        return namelist_to_arr(self.kex_struct.mac_algorithms_client_to_server)

    @property
    def mac_algorithms_server_to_client(self):
        return namelist_to_arr(self.kex_struct.mac_algorithms_server_to_client)

    @property
    def compression_algorithms_client_to_server(self):
        return namelist_to_arr(self.kex_struct.compression_algorithms_client_to_server)

    @property
    def compression_algorithms_server_to_client(self):
        return namelist_to_arr(self.kex_struct.compression_algorithms_server_to_client)


class SSHConnectionState(object):
    def __init__(self, stream, is_client, log, keys):
        self.log = log
        self.is_client = is_client
        self.stream = stream
        self.keys = keys
        self.banner = None
        self.version = None
        self.pub_key = None
        self.seq_nr = 0
        self.recv_enc = None
        self._recv_blocksize = 8
        self._recv_macsize = 0  # 16
        self._etm = False

        self.enc_algo_cs = None
        self.enc_algo_sc = None
        self.mac_alg_cs = None
        self.mac_alg_sc = None
        self.cmp_alg_cs = None
        self.cmp_alg_sc = None
        self.decompressor = None
        self.decompress_after_auth = False
        self.auth_complete = False

        self.kex = None
        self.kex_ongoing = False
        self.kex_complete = False

        self.enc_key = None

        self.last_user_auth_request = None

    def __str__(self):
        return "[Client]" if self.is_client else "[Server]"

    @property
    def shell_prompt(self):
        user = ""
        if self.auth_complete and self.last_user_auth_request is not None:
            user = self.last_user_auth_request.username.data
        return "[{}@{}]$".format(user, "localhost")

    def readline(self):
        data = self.stream.readline()
        return data

    def peek(self, length):
        data = self.stream.peek(length)
        return data[:length]

    def read(self, length):
        data = self.stream.read(length)
        if len(data) != length:
            raise Exception("Only read {} bytes when expected {} bytes".format(len(data), length))
        return data

    def protocol_version_info(self):
        return "Banner: \n{}Version: {}".format(self.banner, self.version)

    def recv_frame(self, expected_type=None):
        first_block = self.read(self._recv_blocksize)
        if self.recv_enc:
            dummy, pktlen_raw = self.recv_enc.decrypt_header(self.seq_nr, first_block, 4)
        else:
            pktlen_raw = first_block[:4]
        pktlen = c_ssh.uint32(pktlen_raw)
        remaining_data_len = 4 + pktlen + self._recv_macsize - self._recv_blocksize
        whole_frame_len = remaining_data_len + self._recv_blocksize

        do_packet_crypto = self.recv_enc is not None
        do_packet_decompression = self.decompressor is not None and (self.auth_complete or not self.decompress_after_auth)
        direction_str = "<-" if self.is_client else "->"
        self.log.protocolv("{} seqnr: {}, totallen: {}, pktlen: {}, macsize: {}, crypto: {}, compression: {}".format(direction_str, self.seq_nr, whole_frame_len, pktlen, self._recv_macsize, do_packet_crypto, do_packet_decompression))
        # self.log.writeline("{} >> {}".format(self, remaining_data_len))
        remaining_data = self.read(remaining_data_len - self._recv_macsize)
        mac = self.read(self._recv_macsize)

        if do_packet_crypto:
            frame_data = self.recv_enc.decrypt_packet(self.seq_nr, first_block, remaining_data, 4, mac)
        else:
            frame_data = first_block[4:] + remaining_data

        payload = frame_data[1:-ord(frame_data[0])]  # Strip of padding
        if do_packet_decompression:
            payload = self.decompressor.decompress(payload)
            if payload is None:
                raise Exception('Decompression failed')

        msg_type = determine_ssh_msg_type(payload)
        self.log.protocolv("{} {} {}".format(direction_str, len(payload), msg_type))
        if expected_type is not None:
            if expected_type != msg_type:
                raise Exception("Recieved frame does not match expected frame type {} vs {}".format(msg_type, expected_type))

        self.seq_nr = (self.seq_nr + 1) & 0xffffffff
        return msg_type, payload

    def recv_version(self):
        banner = ""
        while True:
            line = self.readline()
            if line == "":
                raise Exception("No SSH connection")
            if line.startswith("SSH-"):
                version = line.rstrip()
                self.banner = banner
                self.version = version
                self.log.protocol("{}\n{}\n{}".format(self, self.version, self.banner))
                return
            banner += line

    def process_frame(self, frame_type, frame_data):
        self.log.protocol(self)
        switch_table = {
            c_ssh.MsgType.SSH_MSG_KEXINIT:                      self.process_kex_init,
            c_ssh.MsgType.SSH_MSG_KEXDH_INIT:                   self.process_kex_dh_init,
            c_ssh.MsgType.SSH_MSG_KEXDH_REPLY:                  self.process_kex_dh_reply,
            c_ssh.MsgType.SSH_MSG_NEWKEYS:                      self.process_new_keys,
            c_ssh.MsgType.SSH_MSG_GLOBAL_REQUEST:               self.process_global_request,
            c_ssh.MsgType.SSH_MSG_SERVICE_REQUEST:              self.process_service_request,
            c_ssh.MsgType.SSH_MSG_EXT_INFO:                     self.process_ext_info,
            c_ssh.MsgType.SSH_MSG_USERAUTH_REQUEST:             self.process_user_auth_request,
            c_ssh.MsgType.SSH_MSG_USERAUTH_FAILURE:             self.process_user_auth_failure,
            c_ssh.MsgType.SSH_MSG_USERAUTH_SUCCESS:             self.process_user_auth_success,
            c_ssh.MsgType.SSH_MSG_IGNORE:                       self.process_ignore,
            c_ssh.MsgType.SSH_MSG_CHANNEL_DATA:                 self.process_channel_data,
            c_ssh.MsgType.SSH_MSG_CHANNEL_EXTENDED_DATA:        self.process_channel_extended_data,
            c_ssh.MsgType.SSH_MSG_SERVICE_ACCEPT:               self.process_service_accept,
            c_ssh.MsgType.SSH_MSG_CHANNEL_OPEN:                 self.process_channel_open,
            c_ssh.MsgType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:    self.process_channel_open_confirmation,
            c_ssh.MsgType.SSH_MSG_CHANNEL_REQUEST:              self.process_channel_request,
            c_ssh.MsgType.SSH_MSG_CHANNEL_WINDOW_ADJUST:        self.process_channel_window_adjust,
            c_ssh.MsgType.SSH_MSG_CHANNEL_SUCCESS:              self.process_channel_success,
            c_ssh.MsgType.SSH_MSG_CHANNEL_FAILURE:              self.process_channel_failure,
            c_ssh.MsgType.SSH_MSG_CHANNEL_EOF:                  self.process_channel_eof,
            c_ssh.MsgType.SSH_MSG_CHANNEL_CLOSE:                self.process_channel_close,
            c_ssh.MsgType.SSH_MSG_DISCONNECT:                   self.process_disconnect,
        }

        frame_processor = switch_table.get(frame_type, None)
        if frame_processor is not None:
            frame_processor(frame_data)
        if frame_processor is None:
            self.log.protocol("[{}]".format(frame_type))
            self.log.protocol(repr(frame_data))
        self.log.protocol("")

    def process_disconnect(self, data):
        disconnect = c_ssh.Disconnect(data)
        self.log.protocol("[Disconnect]")
        self.log.protocol(pretty_format_struct_ex(disconnect))

    def process_channel_close(self, data):
        channel_close = c_ssh.Channel(data)
        self.log.protocol("[Channel Close]")
        self.log.protocol(pretty_format_struct_ex(channel_close))

    def process_channel_eof(self, data):
        channel_eof = c_ssh.Channel(data)
        self.log.protocol("[Channel EOF]")
        self.log.protocol(pretty_format_struct_ex(channel_eof))

    def process_channel_success(self, data):
        channel_status = c_ssh.Channel(data)
        self.log.protocol("[Channel Success]")
        self.log.protocol(pretty_format_struct_ex(channel_status))

    def process_channel_failure(self, data):
        channel_status = c_ssh.Channel(data)
        self.log.protocol("[Channel Failure]")
        self.log.protocol(pretty_format_struct_ex(channel_status))

    def process_user_auth_success(self, data):
        self.log.protocol("[User Auth Success]")

    def process_channel_window_adjust(self, data):
        channel_wdw_adjust = c_ssh.ChannelWindowsAdjust(data)
        self.log.protocol("[Channel Window Adjust]")
        self.log.protocol(pretty_format_struct_ex(channel_wdw_adjust))

    def process_channel_request(self, data):
        frame_data = StringIO(data)
        channel_request = c_ssh.ChannelRequest(frame_data)
        self.log.protocol("[Channel Request]")
        self.log.protocol(pretty_format_struct_ex(channel_request))
        request_type = channel_request.request_type.data
        if request_type == "exec":
            command = c_ssh.String(frame_data)
            self.log.info("{} {}".format(self.shell_prompt, command.data))
        elif request_type == "exit-status":
            exit_status = c_ssh.uint32(frame_data)
            self.log.protocol("exit-code: {}".format(exit_status))
            if exit_status != 0:
                self.log.info("process exited with status {}".format(exit_status))

        remaining_data = frame_data.read()
        if remaining_data:
            self.log.protocol(repr(remaining_data))

    def process_channel_open(self, data):
        frame_data = StringIO(data)
        channel_open = c_ssh.ChannelOpen(frame_data)
        remaining_data = frame_data.read()
        self.log.protocol("[Channel Open]")
        self.log.protocol(pretty_format_struct_ex(channel_open))
        if remaining_data:
            self.log.protocol(repr(remaining_data))

    def process_channel_open_confirmation(self, data):
        frame_data = StringIO(data)
        channel_open_confirm = c_ssh.ChannelOpenConfirmation(frame_data)
        remaining_data = frame_data.read()
        self.log.protocol("[Channel Open Confirmation]")
        self.log.protocol(pretty_format_struct_ex(channel_open_confirm))
        if remaining_data:
            self.log.protocol(repr(remaining_data))

    def process_channel_open_failure(self, data):
        channel_open_failure = c_ssh.ChannelOpenFailure(data)
        self.log.protocol("[Channel Open Failure]")
        self.log.protocol(pretty_format_struct_ex(channel_open_failure))

    def process_service_accept(self, data):
        service_accept = c_ssh.ServiceAccept(data)
        self.log.protocol("[Service Accept]")
        self.log.protocol("Service: {}".format(service_accept.service_name.data))

    def process_channel_extended_data(self, data):
        channel_ext_data = c_ssh.ChannelExtendedData(data)
        self.log.protocol("[Channel Extended Data]")
        self.log.protocol(pretty_format_struct_ex(channel_ext_data))
        self.log.info(channel_ext_data.data.data)

    def process_channel_data(self, data):
        channel_data = c_ssh.ChannelData(data)
        self.log.protocol("[Channel Data]")
        self.log.protocol(pretty_format_struct_ex(channel_data))
        self.log.info(channel_data.data.data)

    def process_ignore(self, data):
        self.log.protocol("[Ignore]")

    def process_user_auth_failure(self, data):
        auth_failure = c_ssh.UserAuthFailure(data)
        self.log.info("[User Auth Failure]")
        self.log.info(pretty_format_struct_ex(auth_failure))
        self.log.info("")

    def process_user_auth_request(self, data):
        frame_data = StringIO(data)
        userauth_req = c_ssh.UserAuthRequest(frame_data)
        self.last_user_auth_request = userauth_req
        self.log.info("[User Auth Request]")
        self.log.info(pretty_format_struct_ex(userauth_req))
        if userauth_req.method_name.data == "password":
            dummy_bool = frame_data.read(1)
            password_data = frame_data.read()
            password = c_ssh.String(password_data)
            self.log.info("Password: {}".format(password.data))
        self.log.info("")

    def process_ext_info(self, data):
        extension_info = c_ssh.ExtensionInfo(data)
        self.log.protocol("[Extension Info]")
        for i in range(extension_info.nr_extensions):
            self.log.protocol("{} -> {}".format(extension_info.extension_names[i].data, extension_info.extension_values[i].data))

    def process_service_request(self, data):
        self.log.protocol("[Service Request]")
        svc_req = c_ssh.ServiceRequest(data)
        self.log.protocol("Service Request: {}".format(svc_req.service_name.data))

    def process_global_request(self, data):
        self.log.protocol("[Global Request]")
        global_request = c_ssh.GlobalRequest(data)
        self.log.protocol("Global Request: {}".format(global_request.request_name.data))

    def process_kex_dh_reply(self, data):
        self.log.protocol("[KEX DH Reply]")
        kexdhreply = c_ssh.KeyExchangeDHReply(data)
        self.pub_key = kexdhreply.f
        self.log.protocol("pubkey: {}".format(self.pub_key))

    def process_kex_dh_init(self, data):
        self.log.protocol("[KEX DH Init]")
        kexdhinit = c_ssh.KeyExchangeDHInit(data)
        self.pub_key = kexdhinit.e
        self.log.protocol("pubkey: {}".format(self.pub_key))

    def process_kex_init(self, data):
        self.log.protocol("[KEX Init]")
        kex_struct = c_ssh.KeyExchangeInit(data)
        self.kex = Kex(kex_struct)
        self.log.protocol(self.kex.pretty_str())
        self.kex_ongoing = True
        self.kex_complete = False

    def verify_decryption_key(self, next_tcp_frame):
        # Let's peek the next packet data and try and decrypt the packet
        next_packet_data = self.peek(next_tcp_frame.length)
        next_packet_data = StringIO(next_packet_data)

        first_block = next_packet_data.read(self._recv_blocksize)
        dummy, pktlen_raw = self.recv_enc.decrypt_header(self.seq_nr, first_block, 4)
        pktlen = c_ssh.uint32(pktlen_raw)
        if pktlen > next_tcp_frame.length:
            self.log.protocolv("Decrypted pktlen bigger than packet")
            return False

        #self.log.protocol("VERIFY: {} vs {}".format(next_tcp_frame.length, pktlen))
        remaining_data_len = 4 + pktlen + self._recv_macsize - self._recv_blocksize
        whole_frame_len = remaining_data_len + self._recv_blocksize

        do_packet_crypto = self.recv_enc is not None
        do_packet_decompression = self.decompressor is not None and (self.auth_complete or not self.decompress_after_auth)
        direction_str = "<-" if self.is_client else "->"
        self.log.protocolv("{} [VERIFY DECRYPTION] seqnr: {}, totallen: {}, pktlen: {}, macsize: {}, crypto: {}, compression: {}".format(direction_str, self.seq_nr, whole_frame_len, pktlen, self._recv_macsize, do_packet_crypto, do_packet_decompression))
        # self.log.writeline("{} >> {}".format(self, remaining_data_len))
        remaining_data = next_packet_data.read(remaining_data_len - self._recv_macsize)
        mac = next_packet_data.read(self._recv_macsize)
        try:
            frame_data = self.recv_enc.decrypt_packet(self.seq_nr, first_block, remaining_data, 4, mac)
        except:
            return False
        if frame_data and len(frame_data) == pktlen:
            return True

    def sub_iv(self, iv):
        invocation = int64_from_bytes(iv[4:])
        invocation = (invocation - 1) & 0xffffffffffffffff
        result = iv[:4] + to_bytes(invocation, 8, 'big')
        return result

    def load_decryption_key(self, next_tcp_frame):
        self.log.protocol(self)
        self.log.protocol("Determining decryption key for traffic. Peeking next packet and trying to decrypt with keys..")
        key_loaded = False
        for key in self.keys:
            enc_alg = self.enc_algo_cs if self.is_client else self.enc_algo_sc
            if key.get("cipher_name") == enc_alg:
                key_hex = key.get("key")
                iv_hex = key.get("iv")
                key_raw = key_hex.decode("hex")
                iv_raw = iv_hex.decode("hex"),
                self.log.protocol("Trying key '{}' with iv '{}'".format(key_hex, iv_hex))
                key_loaded = self.try_decryption_key(key_hex, iv_hex, next_tcp_frame)
                if key_loaded:
                    break

        self.log.protocol("")
        if not key_loaded:
            raise Exception("Could not find matching encryption key for traffic!")

    def try_decryption_key(self, key_hex, iv_hex, next_tcp_frame):
        mac_key = None
        key_raw = key_hex.decode("hex")
        iv_raw = iv_hex.decode("hex")

        """
        I have found that for GCM the IV is dumped for the current session state. The IV is modified (iv = iv + 1) for each SSH frame received/sent. 
        So we take the IV and try to bruteforce possible correct IV's by continously substracting from it..
        We can know the upper bound by knowing how many packets there are in the stream.. TODO  
        """
        for i in range(0xff):
        #for i in range(0xffff):
            self.recv_enc = get_encryption(self.enc_algo_sc, key_raw, iv_raw, self.mac_alg_cs, mac_key, self._etm)
            if self.verify_decryption_key(next_tcp_frame):
                self.log.protocol("Key correct!")
                # Reinitialize the encryption state, because verify_decryption_key uses the encrypter and may use up internal encryptions state (stream ciphers)
                self.recv_enc = get_encryption(self.enc_algo_sc, key_raw, iv_raw, self.mac_alg_cs, mac_key, self._etm)
                self.log.protocol("New encryption in affect: {} with key '{}' and iv '{}'".format(self.enc_algo_sc, key_hex, iv_hex))
                return True
            elif "gcm" in self.enc_algo_sc:
                iv_raw = self.sub_iv(iv_raw)
                iv_hex = iv_raw.encode("hex")
                self.log.protocolv("Trying GCM IV '{}'".format(iv_hex))
            else:
                break
        self.log.protocol("Incorrect key")
        return False

    def process_new_keys(self, data):
        self.log.protocol("[New Keys]")
        enc_keysize, enc_ivsize, enc_blocksize, mac_keysize, mac_hashsize, etm = get_encryption_params(self.enc_algo_sc, self.mac_alg_cs)
        self._recv_blocksize = max(8, enc_blocksize)
        self._recv_macsize = mac_hashsize
        self._etm = etm

        self.log.protocol("recv block size: {}".format(self._recv_blocksize))
        self.log.protocol("recv mac size: {}".format(self._recv_macsize))

        cmp_after_auth_cs = get_compression_params(self.cmp_alg_cs)
        self.decompressor = get_decompressor(self.cmp_alg_cs)
        self.decompress_after_auth = cmp_after_auth_cs
        self.log.protocol("New compression in affect: {} after auth: {}".format(self.cmp_alg_cs, self.decompress_after_auth))

        self.kex_ongoing = False
        self.kex_complete = True
