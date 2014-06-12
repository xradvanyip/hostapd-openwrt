# EAP protocol tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hmac
import logging
logger = logging.getLogger()
import select
import struct
import threading
import time

import hostapd

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_OTP = 5
EAP_TYPE_GTC = 6
EAP_TYPE_TLS = 13
EAP_TYPE_LEAP = 17
EAP_TYPE_SIM = 18
EAP_TYPE_TTLS = 21
EAP_TYPE_AKA = 23
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26
EAP_TYPE_TLV = 33
EAP_TYPE_TNC = 38
EAP_TYPE_FAST = 43
EAP_TYPE_PAX = 46
EAP_TYPE_PSK = 47
EAP_TYPE_SAKE = 48
EAP_TYPE_IKEV2 = 49
EAP_TYPE_AKA_PRIME = 50
EAP_TYPE_GPSK = 51
EAP_TYPE_PWD = 52
EAP_TYPE_EKE = 53

def run_pyrad_server(srv, t_stop, eap_handler):
    srv.RunWithStop(t_stop, eap_handler)

def start_radius_server(eap_handler):
    try:
        import pyrad.server
        import pyrad.packet
        import pyrad.dictionary
    except ImportError:
        return None

    class TestServer(pyrad.server.Server):
        def _HandleAuthPacket(self, pkt):
            pyrad.server.Server._HandleAuthPacket(self, pkt)
            if len(pkt[79]) > 1:
                logger.info("Multiple EAP-Message attributes")
                # TODO: reassemble
            eap = pkt[79][0]
            eap_req = self.eap_handler(self.ctx, eap)
            reply = self.CreateReplyPacket(pkt)
            if eap_req:
                if len(eap_req) > 253:
                    logger.info("Need to fragment EAP-Message")
                    # TODO: fragment
                reply.AddAttribute("EAP-Message", eap_req)
            else:
                logger.info("No EAP request available")
            reply.code = pyrad.packet.AccessChallenge

            hmac_obj = hmac.new(reply.secret)
            hmac_obj.update(struct.pack("B", reply.code))
            hmac_obj.update(struct.pack("B", reply.id))

            # reply attributes
            reply.AddAttribute("Message-Authenticator",
                               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            attrs = reply._PktEncodeAttributes()

            # Length
            flen = 4 + 16 + len(attrs)
            hmac_obj.update(struct.pack(">H", flen))
            hmac_obj.update(pkt.authenticator)
            hmac_obj.update(attrs)
            del reply[80]
            reply.AddAttribute("Message-Authenticator", hmac_obj.digest())

            self.SendReplyPacket(pkt.fd, reply)

        def RunWithStop(self, t_stop, eap_handler):
            self._poll = select.poll()
            self._fdmap = {}
            self._PrepareSockets()
            self.t_stop = t_stop
            self.eap_handler = eap_handler
            self.ctx = {}

            while not t_stop.is_set():
                for (fd, event) in self._poll.poll(1000):
                    if event == select.POLLIN:
                        try:
                            fdo = self._fdmap[fd]
                            self._ProcessInput(fdo)
                        except pyrad.server.ServerPacketError as err:
                            logger.info("pyrad server dropping packet: " + str(err))
                        except pyrad.packet.PacketError as err:
                            logger.info("pyrad server received invalid packet: " + str(err))
                    else:
                        logger.error("Unexpected event in pyrad server main loop")

    srv = TestServer(dict=pyrad.dictionary.Dictionary("dictionary.radius"),
                     authport=18138, acctport=18139)
    srv.hosts["127.0.0.1"] = pyrad.server.RemoteHost("127.0.0.1",
                                                     "radius",
                                                     "localhost")
    srv.BindToAddress("")
    t_stop = threading.Event()
    t = threading.Thread(target=run_pyrad_server, args=(srv, t_stop, eap_handler))
    t.start()

    return { 'srv': srv, 'stop': t_stop, 'thread': t }

def stop_radius_server(srv):
    srv['stop'].set()
    srv['thread'].join()

def start_ap(ifname):
    params = hostapd.wpa2_eap_params(ssid="eap-test")
    params['auth_server_port'] = "18138"
    hapd = hostapd.add_ap(ifname, params)
    return hapd

EAP_SAKE_VERSION = 2

EAP_SAKE_SUBTYPE_CHALLENGE = 1
EAP_SAKE_SUBTYPE_CONFIRM = 2
EAP_SAKE_SUBTYPE_AUTH_REJECT = 3
EAP_SAKE_SUBTYPE_IDENTITY = 4

EAP_SAKE_AT_RAND_S = 1
EAP_SAKE_AT_RAND_P = 2
EAP_SAKE_AT_MIC_S = 3
EAP_SAKE_AT_MIC_P = 4
EAP_SAKE_AT_SERVERID = 5
EAP_SAKE_AT_PEERID = 6
EAP_SAKE_AT_SPI_S = 7
EAP_SAKE_AT_SPI_P = 8
EAP_SAKE_AT_ANY_ID_REQ = 9
EAP_SAKE_AT_PERM_ID_REQ = 10
EAP_SAKE_AT_ENCR_DATA = 128
EAP_SAKE_AT_IV = 129
EAP_SAKE_AT_PADDING = 130
EAP_SAKE_AT_NEXT_TMPID = 131
EAP_SAKE_AT_MSK_LIFE = 132

def test_eap_proto_sake(dev, apdev):
    """EAP-SAKE protocol tests"""
    def sake_challenge(ctx):
        logger.info("Test: Challenge subtype")
        return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                           4 + 1 + 3 + 18,
                           EAP_TYPE_SAKE,
                           EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                           EAP_SAKE_AT_RAND_S, 18, 0, 0, 0, 0)

    def sake_handler(ctx, req):
        logger.info("sake_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'], 4 + 1,
                               EAP_TYPE_SAKE)

        if ctx['num'] == 2:
            logger.info("Test: Identity subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY)

        if ctx['num'] == 3:
            logger.info("Test: Identity subtype")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4, 0)
        if ctx['num'] == 4:
            logger.info("Test: Identity subtype (different session id)")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 1, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_PERM_ID_REQ, 4, 0)

        if ctx['num'] == 5:
            logger.info("Test: Identity subtype with too short attribute")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 2)

        if ctx['num'] == 6:
            logger.info("Test: Identity subtype with truncated attribute")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4)

        if ctx['num'] == 7:
            logger.info("Test: Unknown subtype")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, 123)

        if ctx['num'] == 8:
            logger.info("Test: Challenge subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE)

        if ctx['num'] == 9:
            logger.info("Test: Challenge subtype with too short AT_RAND_S")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                               EAP_SAKE_AT_RAND_S, 2)

        if ctx['num'] == 10:
            return sake_challenge(ctx)
        if ctx['num'] == 11:
            logger.info("Test: Unexpected Identity subtype")
            return struct.pack(">BBHBBBBBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 4,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_IDENTITY,
                               EAP_SAKE_AT_ANY_ID_REQ, 4, 0)

        if ctx['num'] == 12:
            return sake_challenge(ctx)
        if ctx['num'] == 13:
            logger.info("Test: Unexpected Challenge subtype")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CHALLENGE,
                               EAP_SAKE_AT_RAND_S, 18, 0, 0, 0, 0)

        if ctx['num'] == 14:
            return sake_challenge(ctx)
        if ctx['num'] == 15:
            logger.info("Test: Confirm subtype without any attributes")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM)

        if ctx['num'] == 16:
            return sake_challenge(ctx)
        if ctx['num'] == 17:
            logger.info("Test: Confirm subtype with too short AT_MIC_S")
            return struct.pack(">BBHBBBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 2,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 2)

        if ctx['num'] == 18:
            logger.info("Test: Unexpected Confirm subtype")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 18, 0, 0, 0, 0)

        if ctx['num'] == 19:
            return sake_challenge(ctx)
        if ctx['num'] == 20:
            logger.info("Test: Confirm subtype with incorrect AT_MIC_S")
            return struct.pack(">BBHBBBBBBLLLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 18,
                               EAP_TYPE_SAKE,
                               EAP_SAKE_VERSION, 0, EAP_SAKE_SUBTYPE_CONFIRM,
                               EAP_SAKE_AT_MIC_S, 18, 0, 0, 0, 0)

        return sake_challenge(ctx)

    srv = start_radius_server(sake_handler)
    if srv is None:
        return "skip"

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 14):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="SAKE", identity="sake user",
                           password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")

        logger.info("Too short password")
        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="SAKE", identity="sake user",
                       password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                       wait_connect=False)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
        if ev is None:
            raise Exception("Timeout on EAP start")
        time.sleep(0.1)
    finally:
        stop_radius_server(srv)

def test_eap_proto_leap(dev, apdev):
    """EAP-LEAP protocol tests"""
    def leap_handler(ctx, req):
        logger.info("leap_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        if ctx['num'] == 2:
            logger.info("Test: Unexpected version")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               0, 0, 0)

        if ctx['num'] == 3:
            logger.info("Test: Invalid challenge length")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 0)

        if ctx['num'] == 4:
            logger.info("Test: Truncated challenge")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 8)

        if ctx['num'] == 5:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 6:
            logger.info("Test: Missing payload in Response")
            return struct.pack(">BBHB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        if ctx['num'] == 7:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 8:
            logger.info("Test: Unexpected version in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               0, 0, 8)

        if ctx['num'] == 9:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 10:
            logger.info("Test: Invalid challenge length in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 0)

        if ctx['num'] == 11:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 12:
            logger.info("Test: Truncated challenge in Response")
            return struct.pack(">BBHBBBB", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_LEAP,
                               1, 0, 24)

        if ctx['num'] == 13:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 14:
            logger.info("Test: Invalid challange value in Response")
            return struct.pack(">BBHBBBB6L", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_LEAP,
                               1, 0, 24,
                               0, 0, 0, 0, 0, 0)

        if ctx['num'] == 15:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 16:
            logger.info("Test: Valid challange value in Response")
            return struct.pack(">BBHBBBB24B", EAP_CODE_RESPONSE, ctx['id'],
                               4 + 1 + 3 + 24,
                               EAP_TYPE_LEAP,
                               1, 0, 24,
                               0x48, 0x4e, 0x46, 0xe3, 0x88, 0x49, 0x46, 0xbd,
                               0x28, 0x48, 0xf8, 0x53, 0x82, 0x50, 0x00, 0x04,
                               0x93, 0x50, 0x30, 0xd7, 0x25, 0xea, 0x5f, 0x66)

        if ctx['num'] == 17:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 18:
            logger.info("Test: Success")
            return struct.pack(">BBHB", EAP_CODE_SUCCESS, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)
        # hostapd will drop the next frame in the sequence

        if ctx['num'] == 19:
            logger.info("Test: Valid challenge")
            return struct.pack(">BBHBBBBLL", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3 + 8,
                               EAP_TYPE_LEAP,
                               1, 0, 8, 0, 0)
        if ctx['num'] == 20:
            logger.info("Test: Failure")
            return struct.pack(">BBHB", EAP_CODE_FAILURE, ctx['id'],
                               4 + 1,
                               EAP_TYPE_LEAP)

        return None

    srv = start_radius_server(leap_handler)
    if srv is None:
        return "skip"

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 12):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="LEAP", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            if i == 10:
                logger.info("Wait for additional roundtrip")
                time.sleep(1)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_md5(dev, apdev):
    """EAP-MD5 protocol tests"""
    def md5_handler(ctx, req):
        logger.info("md5_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_MD5)

        if ctx['num'] == 2:
            logger.info("Test: Zero-length challenge")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_MD5,
                               0)

        if ctx['num'] == 3:
            logger.info("Test: Truncated challenge")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_MD5,
                               1)

        if ctx['num'] == 4:
            logger.info("Test: Shortest possible challenge and name")
            return struct.pack(">BBHBBBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 3,
                               EAP_TYPE_MD5,
                               1, 0xaa, ord('n'))

        return None

    srv = start_radius_server(md5_handler)
    if srv is None:
        return "skip"

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 4):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="MD5", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"], timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)

def test_eap_proto_otp(dev, apdev):
    """EAP-OTP protocol tests"""
    def otp_handler(ctx, req):
        logger.info("otp_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        if ctx['num'] == 1:
            logger.info("Test: Empty payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_OTP)
        if ctx['num'] == 2:
            logger.info("Test: Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'],
                               4)

        if ctx['num'] == 3:
            logger.info("Test: Challenge included")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_OTP,
                               ord('A'))
        if ctx['num'] == 4:
            logger.info("Test: Success")
            return struct.pack(">BBH", EAP_CODE_SUCCESS, ctx['id'],
                               4)

        return None

    srv = start_radius_server(otp_handler)
    if srv is None:
        return "skip"

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 1):
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="OTP", identity="user", password="password",
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.1)
            dev[0].request("REMOVE_NETWORK all")

        dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                       eap="OTP", identity="user", wait_connect=False)
        ev = dev[0].wait_event(["CTRL-REQ-OTP"])
        if ev is None:
            raise Exception("Request for password timed out")
        id = ev.split(':')[0].split('-')[-1]
        dev[0].request("CTRL-RSP-OTP-" + id + ":password")
        ev = dev[0].wait_event("CTRL-EVENT-EAP-SUCCESS")
        if ev is None:
            raise Exception("Success not reported")
    finally:
        stop_radius_server(srv)

EAP_GPSK_OPCODE_GPSK_1 = 1
EAP_GPSK_OPCODE_GPSK_2 = 2
EAP_GPSK_OPCODE_GPSK_3 = 3
EAP_GPSK_OPCODE_GPSK_4 = 4
EAP_GPSK_OPCODE_FAIL = 5
EAP_GPSK_OPCODE_PROTECTED_FAIL = 6

def test_eap_proto_gpsk(dev, apdev):
    """EAP-GPSK protocol tests"""
    def gpsk_handler(ctx, req):
        logger.info("gpsk_handler - RX " + req.encode("hex"))
        if 'num' not in ctx:
            ctx['num'] = 0
        ctx['num'] = ctx['num'] + 1
        if 'id' not in ctx:
            ctx['id'] = 1
        ctx['id'] = (ctx['id'] + 1) % 256

        idx = 0

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Missing payload")
            return struct.pack(">BBHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1,
                               EAP_TYPE_GPSK)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unknown opcode")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               255)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected GPSK-3")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Too short GPSK-1")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Truncated ID_Server")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Missing RAND_Server")
            return struct.pack(">BBHBBH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Missing CSuite_List")
            return struct.pack(">BBHBBH8L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Truncated CSuite_List")
            return struct.pack(">BBHBBH8LH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Empty CSuite_List")
            return struct.pack(">BBHBBH8LH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Invalid CSuite_List")
            return struct.pack(">BBHBBH8LHB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               1, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 No supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Unexpected GPSK-1")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite but too short key")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: Too short GPSK-3")
            return struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in RAND_Peer")
            return struct.pack(">BBHBB8L", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 32,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_3,
                               0, 0, 0, 0, 0, 0, 0, 0)

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing RAND_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in RAND_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8L", 1, 1, 1, 1, 1, 1, 1, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8L", 0, 0, 0, 0, 0, 0, 0, 0)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Truncated ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LH", 0, 0, 0, 0, 0, 0, 0, 0, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in ID_Server")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHB", 0, 0, 0, 0, 0, 0, 0, 0, 1, ord('B'))
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBHB8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 3 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 1, ord('A'),
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in ID_Server (same length)")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[15:47]
            msg += struct.pack(">8LHB", 0, 0, 0, 0, 0, 0, 0, 0, 1, ord('B'))
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing CSuite_Sel")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LH", 0, 0, 0, 0, 0, 0, 0, 0, 0)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Mismatch in CSuite_Sel")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing len(PD_Payload_Block)")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Truncated PD_Payload_Block")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 2,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Missing MAC")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 3,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHHB",
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 123)
            return msg

        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-1 Supported CSuite")
            return struct.pack(">BBHBBH8LHLH", EAP_CODE_REQUEST, ctx['id'],
                               4 + 1 + 1 + 2 + 32 + 2 + 6,
                               EAP_TYPE_GPSK,
                               EAP_GPSK_OPCODE_GPSK_1, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               6, 0, 1)
        idx += 1
        if ctx['num'] == idx:
            logger.info("Test: GPSK-3 Incorrect MAC")
            msg = struct.pack(">BBHBB", EAP_CODE_REQUEST, ctx['id'],
                              4 + 1 + 1 + 32 + 32 + 2 + 6 + 3 + 16,
                              EAP_TYPE_GPSK,
                              EAP_GPSK_OPCODE_GPSK_3)
            msg += req[14:46]
            msg += struct.pack(">8LHLHHB4L",
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 123,
                               0, 0, 0, 0)
            return msg

        return None

    srv = start_radius_server(gpsk_handler)
    if srv is None:
        return "skip"

    try:
        hapd = start_ap(apdev[0]['ifname'])

        for i in range(0, 27):
            if i == 12:
                pw = "short"
            else:
                pw = "abcdefghijklmnop0123456789abcdef"
            dev[0].connect("eap-test", key_mgmt="WPA-EAP", scan_freq="2412",
                           eap="GPSK", identity="user", password=pw,
                           wait_connect=False)
            ev = dev[0].wait_event(["CTRL-EVENT-EAP-PROPOSED-METHOD"],
                                   timeout=15)
            if ev is None:
                raise Exception("Timeout on EAP start")
            time.sleep(0.05)
            dev[0].request("REMOVE_NETWORK all")
    finally:
        stop_radius_server(srv)