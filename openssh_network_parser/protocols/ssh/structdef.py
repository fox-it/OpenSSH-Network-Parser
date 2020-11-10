from dissect import cstruct

c_ssh_def = """

struct NameList
{
    uint32 length;
    char strlist[length];
};

struct String
{
    uint32 length;
    char data[length];
};

struct MPInt
{
    uint32 length;
    char data[length];
};


struct SSH_FRAME
{
    uint32 packet_length;
    uint8 padding_length;
    char payload[packet_length - padding_length - 1];
    char padding[padding_length];    
};

enum MsgType : uint8
{
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_EXT_INFO = 7,
    SSH_MSG_NEWCOMPRESS = 8,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60,
    SSH_MSG_USERAUTH_INFO_RESPONSE = 61,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100
};

struct KeyExchangeDHInit
{
    MsgType msg_type;
    MPInt e;
};

struct KeyExchangeDHReply
{
    MsgType msg_typeKeyExchangeInit;
    String host_key_data;
    MPInt f;
    string sig;
};

struct KeyExchangeInit
{  
    MsgType msg_type;
    char cookie[16];
    NameList kex_algorithms;
    NameList server_host_key_algorithms;
    NameList encryption_algorithms_client_to_server;
    NameList encryption_algorithms_server_to_client;
    NameList mac_algorithms_client_to_server;
    NameList mac_algorithms_server_to_client;
    NameList compression_algorithms_client_to_server;
    NameList compression_algorithms_server_to_client;
    NameList languages_client_to_server;
    NameList languages_server_to_client;
    uint8 first_kex_packet_follows;
    //uint32 reserved;
};

struct ExtensionInfo
{
    MsgType msg_type;
    uint32 nr_extensions;
    String extension_names[nr_extensions];
    String extension_values[nr_extensions];
};

struct ServiceRequest
{
    MsgType msg_type;
    String service_name;
};

struct ServiceAccept
{
    MsgType msg_type;
    String service_name;
};

struct UserAuthRequest
{
    MsgType msg_type;
    String username;
    String service_name;
    String method_name;
};

struct UserAuthFailure
{
    MsgType msg_type;
    NameList auth_continue;
    uint8 partial_success;
};

struct GlobalRequest
{
    MsgType msg_type;
    String request_name;
    uint8 want_reply;
};

struct ChannelData
{
    MsgType msg_type;
    uint32 recipient_channel;
    String data;
};

struct ChannelExtendedData
{
    MsgType msg_type;
    uint32 recipient_channel;
    uint32 data_type_code;
    String data;
};

struct ChannelOpen
{
    MsgType msg_type;
    String channel_type;
    uint32 sender_channel;
    uint32 initial_window_size;
    uint32 max_packet_size;
};

struct ChannelOpenConfirmation
{
    MsgType msg_type;
    uint32 recipient_channel;
    uint32 sender_channel;
    uint32 initial_window_size;
    uint32 maximum_packet_size;
};

enum SSHOpen : uint32
{
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4
};


struct ChannelOpenFailure
{
    MsgType msg_type;
    uint32 recipient_channel;
    SSHOpen reason_code;
    String description;
    String language_tag;
};

struct ChannelRequest
{
    MsgType msg_type;
    uint32 recipient_channel;
    String request_type;
    uint8 want_reply;
};

struct ChannelWindowsAdjust
{
    MsgType msg_type;
    uint32 recipient_channel;
    uint32 bytes_to_add;
};

struct Channel
{
    MsgType msg_type;
    uint32 recipient_channel;
};

enum DisconnectReason : uint32
{
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
};

struct Disconnect
{
    MsgType msg_type;
    DisconnectReason reason_code;
    String description;
    String language_tag;
};
"""

c_ssh = cstruct.cstruct()
c_ssh.load(c_ssh_def)
c_ssh.endian = ">"
