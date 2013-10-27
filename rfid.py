#!/usr/bin/env python

import time
import smartcard
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.util import toHexString, toASCIIString, toASCIIBytes
from smartcard.ATR import ATR
from smartcard.Exceptions import SmartcardException, NoReadersException, CardConnectionException, NoCardException

# Try to use pyscard exceptions so it's easier to catch
class UnsupportedReader(SmartcardException):
    pass

class ReaderException(SmartcardException):
    pass

class PN532Exception(SmartcardException):
    pass

class SAMException(SmartcardException):
    pass


DEBUG = True
DEBUG = False

"""
Sources:
http://www.proxmark.org/files/Documents/NFC/ACS_API_ACR122.pdf
http://www.acs.com.hk/drivers/chi/API-ACR122USAM-2.01.pdf
http://www.nxp.com/documents/user_manual/141520.pdf
https://code.google.com/p/nfcip-java/source/browse/trunk/nfcip-java/doc/ACR122_PN53x.txt
https://code.google.com/p/understand/wiki/SmartCards
http://www.ecma-international.org/publications/files/ECMA-ST-ARCH/ECMA-340%201st%20edition%20December%202002.pdf

pyscard's Session() is a bit broken, so we define our own interface here.

You can either poll Pcsc.readers(), or call Pcsc.reader(), which defaults to the first.
"""

class Pcsc(object):
    @classmethod
    def wrapreader(self, reader):
        if reader.name.startswith('ACS'):
            return AcsReader(reader)
        return UnknownReader(reader)

    @classmethod
    def readers(self):
        readers = map(self.wrapreader, smartcard.System.readers())
        return readers

    @classmethod
    def reader(self, readernum=None):
        readers = self.readers()

        if not readers:
            raise NoReadersException()

        if readernum is None:
            readernum = 0

        return readers[readernum]


class PcscReader(object):
    def __init__(self, reader):
        self.reader = reader
        self.name = reader.name

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.name)

    def open(self):
        self.conn = self.reader.createConnection()
        self.conn.connect()

        if DEBUG:
            observer = ConsoleCardConnectionObserver()
            self.conn.addObserver(observer)

    def close(self):
        # PCSCCardConnection.__del__ calls disconnect, but
        # let's do it in case someone's taken a reference
        self.conn.disconnect()
        self.conn = None
        self.reader = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class UnsupportedReader(PcscReader):
    def open(self):
        raise UnsupportedReader()

    def close(self):
        pass


class APDU(object):
    def __init__(self, cls, ins, p1=0, p2=0, lc=None, data=None, le=None):
        self.cls = cls
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        if data is None:
            data = []
        self.data = data
        if lc is None:
            lc = len(data)
        self.lc = lc
        self.le = []
        if le is not None:
            self.le = [le]

    @property
    def bytes(self):
        if len(self.data) > 255:
            raise ValueError('APDU payload too long')
        return [self.cls, self.ins, self.p1, self.p2, self.lc] + self.data + self.le

    def __iter__(self):
        return iter(self.bytes)

    @classmethod
    def frombytes(self, bytes):
        args = bytes[:4]
        lc = bytes[4]
        if 5 + lc != len(bytes):
            raise ValueError('Length %s is incorrect for APDU length %s' % (5 + lc, len(bytes)))
        args.append(bytes[5:])
        return APDU(*args)


class AcsReader(PcscReader):
    def __init__(self, reader):
        PcscReader.__init__(self, reader)
        self.pn532 = Pn532(self)

    def open(self):
        PcscReader.open(self)

        # We could pass this into connect, but this is clearer
        self.atr = ATR(self.conn.getATR())
        if DEBUG:
            print 'ATR: %s' % self.atr
            self.atr.dump()

        if not self.atr.isT0Supported():
            self.close()
            raise CardConnectionException('Reader reports T0 protocol not supported')

        if DEBUG:
            print 'Firmware version %s' % self.firmware_version()

        self.pn532.set_retries(0, 0, 0)

    def send(self, apdu):
        resp, sw1, sw2 = self.conn.transmit(list(apdu))
        return resp, sw1, sw2


    def firmware_version(self):
        apdu = APDU(0xff, 0, 0x48)
        resp, sw1, sw2 = self.send(apdu)
        return toASCIIString(resp + [sw1, sw2])


    def led_buzzer(self, red=None, green=None, blink=None, buzzer=None):
        led_ctl = 0
        if red is not None:
            led_ctl |= 0x4
            if not isinstance(red, (list, tuple)):
                red = False, False, red

            initial_led, blink_led, final_led = red
            led_ctl |= 0x1 if final_led else 0
            led_ctl |= 0x10 if initial_led else 0
            led_ctl |= 0x40 if blink_led else 0
            
        if green is not None:
            led_ctl |= 0x8
            if not isinstance(green, (list, tuple)):
                green = False, False, green

            initial_led, blink_led, final_led = green
            led_ctl |= 0x2 if final_led else 0
            led_ctl |= 0x20 if initial_led else 0
            led_ctl |= 0x80 if blink_led else 0
        
        initial_delay, blink_delay, blink_count = 0, 0, 0
        if blink:
            initial_delay, blink_delay, blink_count = blink
            initial_delay = initial_delay / 100
            blink_delay = blink_delay / 100

        buzz_ctl = 0
        if buzzer:
            initial_buzz, blink_buzz = buzzer
            buzz_ctl = 0
            buzz_ctl |= 0x1 if initial_buzz else 0
            buzz_ctl |= 0x2 if blink_buzz else 0

        extra = [initial_delay, blink_delay, blink_count, buzz_ctl]

        apdu = APDU(0xff, 0, 0x40, led_ctl, data=extra)
        resp, sw1, sw2 = self.send(apdu)
        if sw1 != 0x90:
            raise ReaderException('Error setting LEDs %02x%02x' % (sw1, sw2))

        red, green = map(bool, [sw2 & 0x1, sw2 & 0x2])
        return red, green


    def red_on(self):
        self.led_buzzer(red=True)

    def red_off(self):
        self.led_buzzer(red=False)

    def green_on(self):
        self.led_buzzer(green=True)

    def green_off(self):
        self.led_buzzer(green=False)

    def denied(self):
        self.led_buzzer(
            red=[True, False, False],
            green=[True, True, False],
            blink=[500, 300, 3],
            buzzer=[True, False]
        )


    def send_to_pn532(self, apdu):
        apdu = APDU(0xff, 0, 0, data=apdu)
        resp, sw1, sw2 = self.send(apdu)

        if sw1 != 0x61:
            raise ReaderException('Error communicating with PN532: %02x%02x' % (sw1, sw2))

        apdu = APDU(0xff, 0xc0, lc=sw2)
        resp, sw1, sw2 = self.send(apdu)

        return resp, sw1, sw2

    def send_to_sam(self, p1, p2, lc):
        if (self.atr.TS, self.atr.T0) == (0x3b, 0):
            raise SAMException('SAM not reported present')

        resp, sw1, sw2 = self.send(APDU(0x80, 0x14, p1, p2, lc))
        if (sw1, sw2) != (0x90, 0):
            raise ReaderException('Error communicating with SAM: %02x%02x' % (sw1, sw2))

        return resp

    def sam_serial(self):
        return self.send_to_sam(0, 0, 8)

    def sam_id(self):
        return self.send_to_sam(4, 0, 6)

    def sam_os(self):
        resp = self.send_to_sam(6, 0, 8)
        os = resp[:4]
        rest = resp[4:]
        return toASCIIString(os), rest


class Pn532(object):
    BITRATES = [106, 212, 424]
    MODULATIONS = {
        0x00: 'Mifare/ISO14443/ISO18092 106kbps',
        0x01: 'ISO18092 active',
        0x02: 'Jewel',
        0x10: 'FeliCa/ISO18092 passive 212/424kbps',
    }
    ENCODINGS = ['Type A', 'FeliCa 212kbps', 'FeliCa 424kbps', 'Type B', 'Type 1']
    FIRMWARE_FEATURES = ['Type A', 'Type B', 'ISO18092']

    def __init__(self, reader):
        self.reader = reader

    def send(self, cc, data=None):
        if data is None:
            data = []

        tfi = 0xd4 # host to controller
        resp, sw1, sw2 = self.reader.send_to_pn532([tfi, cc] + data)
        tfi2, cc2 = resp[:2]
        if (tfi2, cc2) != (0xd5, cc + 1):
            raise PN532Exception('Error returned: %02x%02x' % (tfi2, cc2))

        return resp[2:]

    def test(self, test, params):
        # INTERESTING
        resp = self.send(0, [test] + params)
        return resp

    def firmware(self):
        resp = self.send(0x2)
        ic, ver, rev, support = resp
        icname = {0x32: 'PN532'}.get(ic, 'Unknown %02x' % ic)
        features = []
        for n, f in enumerate(self.FIRMWARE_FEATURES):
            if support & (1 << n):
                features.append(f)

        info = dict(
            chip = icname,
            version = (ver, rev),
            features = features,
        )
        return info

    def status(self):
        resp = self.send(0x4)
        r = iter(resp)

        err = r.next()
        field = r.next()
        nbtg = r.next()

        tags = []
        for tag in range(nbtg):
            tags.append(dict(
                logical_id = r.next(),
                rx_kbps = self.BITRATES[r.next()],
                tx_kbps = self.BITRATES[r.next()],
                modulation = self.MODULATIONS[r.next()],
            ))

        sam = r.next()

        status = dict(
            error = err,
            field = bool(field),
            tags = tags,
        )

        return status

    # TODO: registers and GPIO

    def set_params(self, nad=False, cid=False, atr_res=True, rats=True, picc=True, nopreamble=False):
        flags = 0
        flags |= 0x1 if nad else 0
        flags |= 0x2 if cid else 0
        flags |= 0x4 if atr_res else 0
        flags |= 0x10 if rats else 0 # try to use ISO14443-4
        flags |= 0x20 if picc else 0
        flags |= 0x40 if nopreamble else 0

        return self.send(0x12, [flags])

    def shutdown(self, wakeup, interrupt=None):
        args = [wakeup]
        if interrupt is not None:
            args.append(interrupt)
        return self.send(0x16, args)

    def set_radio(self, item, data):
        return self.send(0x32, [item] + data)

    def power_on(self):
        return self.set_radio(1, [1])

    def power_off(self):
        return self.set_radio(1, [0])

    def set_retries(self, atr_req=0xff, psl_req=1, passive=0xff):
        return self.set_radio(5, [atr_req, psl_req, passive])


    def send_to_tag(self, tag, data):
        resp = self.send(0x40, [tag] + list(data))
        if resp[0] != 0:
            raise PN532Exception('Unexpected status %02x' % resp[0])
        return resp[1:]

    def halt_tag(self):
        resp = self.send(0x44, [1])

    def scan(self, max_tags=1, encoding='Type A', data=None):
        # TODO: try max_tags=2
        if data is None:
            data = []
            if encoding == 'Type B':
                data = [0]
            elif encoding.startswith('FeliCa'):
                # This is suggested in the datasheet, but doesn't seem to work
                data = [0x00, 0xff, 0xff, 0x00, 0x00]

        brty = self.ENCODINGS.index(encoding)
        resp = self.send(0x4a, [max_tags, brty] + data)

        r = iter(resp)
        nbtg = r.next()
        if not nbtg:
            raise NoCardException()

        tags = []
        if brty == 0:
            for i in range(nbtg):
                tagtype = 0x10
                tags.append(self.parse_tag(tagtype, r))

        else:
            raise NotImplementedError()

        return tags

    def autoscan(self, polls=1, ms=150, types=[0x20, 0x23, 0x4, 0x10, 0x11, 0x12]):
        if polls is None:
            polls = 0xff
        period = ms / 150

        resp = self.send(0x60, [polls, period] + types)

        r = iter(resp)
        nbtg = r.next()
        if not nbtg:
            raise NoCardException()

        tags = []
        for i in range(nbtg):
            tagtype = r.next()
            length = r.next()

            taginfo = [r.next() for i in range(length)]
            tags.append(self.parse_tag(tagtype, iter(taginfo)))

        return tags

    # Move to tag.py
    def parse_tag(self, tagtype, r):
        target = r.next()

        if tagtype in (0x10, 0x20):
            sens_res = (r.next() << 8) + r.next()
            sel_res = r.next()

            uidlen = r.next()
            uid = ''.join('%02x' % r.next() for i in range(uidlen))

            tag = Tag(self, target, sens_res, sel_res)
            tag.uid = uid

            if tagtype == 0x20:
                atslen = r.next()
                ats = [r.next() for i in range(atslen - 1)]
                tag.ats = ats

        elif tagtype == 0x23:
            atqb = [r.next() for i in range(12)]

            arlen = r.next()
            ar = [r.next() for i in range(arlen)]

        elif tagtype == 0x11:
            prlen = r.next()
            pol_res = [r.next() for i in range(prlen - 1)]
            p = iter(pol_res)

            resp_code = p.next()
            uid = ''.join('%02x' % p.next() for i in range(8))
            print uid

        elif tagtype == 0x4:
            atqa = (r.next() << 8) + r.next()
            uid = ''.join('%02x' % r.next() for i in range(4))

        return tag


from tag import Tag

if __name__ == '__main__':
    with Pcsc.reader() as reader:
        #reader.denied()
        #time.sleep(1)

        #print toASCIIString(reader.sam_id())
        #print toHexString(reader.sam_serial())
        #print reader.sam_os()
        
        p = reader.pn532
        #print p.firmware()
        #p.shutdown(0)
        #p.set_params(rats=False)

        tags = p.scan()
        #tags = p.autoscan()
        print len(tags)
        print 'UID: %s' % tags[0].uid
        print 'ATR: %s' % toHexString(tags[0].ats)

        #print p.status()
        #p.halt_tag()


