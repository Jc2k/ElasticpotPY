import json
import sys
import struct
import socket
import hashlib
import logging
import time
import threading
import ssl

logger = logging.getLogger('pyhpfeeds')


BUFSIZ = 16384

OP_ERROR        = 0
OP_INFO         = 1
OP_AUTH         = 2
OP_PUBLISH      = 3
OP_SUBSCRIBE    = 4

MAXBUF = 1024**2

SIZES = {
    OP_ERROR: 5 + MAXBUF,
    OP_INFO: 5 + 256 + 20,
    OP_AUTH: 5 + 256 + 20,
    OP_PUBLISH: 5 + MAXBUF,
    OP_SUBSCRIBE: 5 + 256*2,
}


def strpack8(x):
    # packs a string with 1 byte length field
    if isinstance(x, str): x = x.encode('latin1')
    return struct.pack('!B', len(x)) + x


def strunpack8(x):
    # unpacks a string with 1 byte length field
    l = x[0]
    return x[1:1+l], x[1+l:]


def msghdr(op, data):
    return struct.pack('!iB', 5 + len(data), op) + data


def msgpublish(ident, chan, data):
    return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)


def msgsubscribe(ident, chan):
    if isinstance(chan, str): chan = chan.encode('latin1')
    return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)


def msgauth(rand, ident, secret):
    hash = hashlib.sha1(bytes(rand) + secret.encode('utf-8')).digest()
    return msghdr(OP_AUTH, strpack8(ident) + hash)


class UnpackError(Exception):
    pass

class FeedException(Exception):
    pass

class FeedUnpacker(object):

    def __init__(self):
        self.buf = bytearray()

    def __iter__(self):
        return self

    def __next__(self):
        return self.unpack()

    def feed(self, data):
        self.buf.extend(data)

    def unpack(self):
        if len(self.buf) < 5:
            raise StopIteration('No message.')

        ml, opcode = struct.unpack('!iB', self.buf[0:5])
        if ml > SIZES.get(opcode, MAXBUF):
            raise UnpackError('Not respecting MAXBUF.')

        if len(self.buf) < ml:
            raise StopIteration('No message.')

        data = bytearray(self.buf[5:])
        del self.buf[:ml]
        return opcode, data


class Disconnect(Exception):
    pass


class Client(object):

    def __init__(self, host, port, ident, secret, timeout=3, reconnect=True, sleepwait=20):
        self.host, self.port = host, port
        self.ident, self.secret = ident, secret
        self.timeout = timeout
        self.reconnect = reconnect
        self.sleepwait = sleepwait
        self.brokername = 'unknown'
        self.connected = False
        self.stopped = False
        self.s = None
        self.connecting_lock = threading.Lock()
        self.subscriptions = set()
        self.unpacker = FeedUnpacker()

        self.tryconnect()

    def makesocket(self, addr_family):
        return socket.socket(addr_family, socket.SOCK_STREAM)

    def recv(self):
        try:
            d = self.s.recv(BUFSIZ)
        except socket.timeout:
            return ""
        except socket.error as e:
            logger.warn("Socket error: %s", e)
            raise Disconnect()

        if not d: raise Disconnect()
        return d

    def send(self, data):
        try:
            self.s.sendall(data)
        except socket.timeout:
            logger.warn("Timeout while sending - disconnect.")
            raise Disconnect()
        except socket.error as e:
            logger.warn("Socket error: %s", e)
            raise Disconnect()

        return True

    def tryconnect(self):
        with self.connecting_lock:
            if not self.connected:
                while True:
                    try:
                        self.connect()
                        break
                    except socket.error as e:
                        logger.warn('Socket error while connecting: {0}'.format(e))
                        time.sleep(self.sleepwait)
                    except FeedException as e:
                        logger.warn('FeedException while connecting: {0}'.format(e))
                        time.sleep(self.sleepwait)
                    except Disconnect as e:
                        logger.warn('Disconnect while connecting.')
                        time.sleep(self.sleepwait)

    def connect(self):
        self.close_old()

        logger.info('connecting to {0}:{1}'.format(self.host, self.port))

        # Try other resolved addresses (IPv4 or IPv6) if failed.
        ainfos = socket.getaddrinfo(self.host, 1, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for ainfo in ainfos:
            addr_family = ainfo[0]
            addr = ainfo[4][0]
            try:
                self.s = self.makesocket(addr_family)
                self.s.settimeout(self.timeout)
                self.s.connect((addr, self.port))
            except:
                import traceback
                traceback.print_exc()
                #print 'Could not connect to broker. %s[%s]' % (self.host, addr)
                continue
            else:
                self.connected = True
                break

        if self.connected == False:
            raise FeedException('Could not connect to broker [%s].' % (self.host))

        try: d = self.s.recv(BUFSIZ)
        except socket.timeout: raise FeedException('Connection receive timeout.')

        self.unpacker.feed(d)
        for opcode, data in self.unpacker:
            if opcode == OP_INFO:
                name, rand = strunpack8(data)
                logger.debug('info message name: {0}, rand: {1}'.format(name, repr(rand)))
                self.brokername = name

                self.send(msgauth(rand, self.ident, self.secret))
                break
            else:
                raise FeedException('Expected info message at this point.')

        self.s.settimeout(None)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if sys.platform in ('linux2', ):
            self.s.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 10)

    def run(self, message_callback, error_callback):
        while not self.stopped:
            self._subscribe()
            while self.connected:
                try:
                    d = self.recv()
                    self.unpacker.feed(d)

                    for opcode, data in self.unpacker:
                        if opcode == OP_PUBLISH:
                            rest = buffer(data, 0)
                            ident, rest = rest[1:1+ord(rest[0])], buffer(rest, 1+ord(rest[0]))
                            chan, content = rest[1:1+ord(rest[0])], buffer(rest, 1+ord(rest[0]))

                            message_callback(str(ident), str(chan), content)
                        elif opcode == OP_ERROR:
                            error_callback(data)

                except Disconnect:
                    self.connected = False
                    logger.info('Disconnected from broker.')
                    break

                # end run loops if stopped
                if self.stopped: break

            if not self.stopped and self.reconnect:
                # connect again if disconnected
                self.tryconnect()

        logger.info('Stopped, exiting run loop.')

    def wait(self, timeout=1):
        self.s.settimeout(timeout)

        try:
            d = self.recv()
            if not d: return None

            self.unpacker.feed(d)
            for opcode, data in self.unpacker:
                if opcode == OP_ERROR:
                    return data
        except Disconnect:
            pass

        return None

    def close_old(self):
        if self.s:
            try: self.s.close()
            except: pass

    def subscribe(self, chaninfo):
        if type(chaninfo) == str:
            chaninfo = [chaninfo,]
        for c in chaninfo:
            self.subscriptions.add(c)

    def _subscribe(self):
        for c in self.subscriptions:
            try:
                logger.debug('Sending subscription for {0}.'.format(c))
                self.send(msgsubscribe(self.ident, c))
            except Disconnect:
                self.connected = False
                logger.info('Disconnected from broker (in subscribe).')
                if not self.reconnect: raise
                break

    def publish(self, chaninfo, data):
        if type(chaninfo) == str:
            chaninfo = [chaninfo,]
        for c in chaninfo:
            try:
                self.send(msgpublish(self.ident, c, data.encode('utf-8')))
            except Disconnect:
                self.connected = False
                logger.info('Disconnected from broker (in publish).')
                if self.reconnect:
                    self.tryconnect()
                else:
                    raise

    def stop(self):
        self.stopped = True

    def close(self):
        try: self.s.close()
        except: logger.debug('Socket exception when closing (ignored though).')


class Output(object):
    
    def __init__(self, config):
        self.channel = config['channel']
        self._feed = Client(
            config['host'],
            int(config['port']),
            config['ident'],
            config['secret']
        )
        self._feed.s.settimeout(0.01)

    def send(self, event):
        self._feed.publish([self.channel], json.dumps(event))
