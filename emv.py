#!/usr/bin/env python

from smartcard.util import toHexString, toASCIIString, toASCIIBytes, toBytes
from ber import Tags, BERWithTags
from collections import OrderedDict
from os import urandom
from common import TagException

class EMVError(TagException):
    pass

class EMVException(TagException):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        msg = ''
        try:
            msg = ' %s' % EMV.STATUSES[sw1]
            msg = '%s (%s)' % (msg, EMV.STATUSES[(sw1, sw2)])
        except KeyError:
            pass

        msg = '%02x%02x%s' % (sw1, sw2, msg)
        TagException.__init__(self, msg)


"""
http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_5_basic_organizations.aspx ff.
http://blog.saush.com/2006/09/08/getting-information-from-an-emv-chip-card/
http://www.openscdp.org/scripts/tutorial/emv/
http://www.emvlab.org/emvtags/all/
https://www.eftlab.co.uk/index.php/site-map/knowledge-base/145-emv-nfc-tags
https://www.paypass.com/Term_TA/PP_Test_Cases_L2_%20Oct_10.pdf

Very useful (e.g. EMV_REFERENCE)
https://code.google.com/p/cardpeek/source/browse/trunk/dot_cardpeek_dir/scripts/emv.lua

https://github.com/sasc999/javaemvreader/blob/master/src/main/java/sasc/emv/EMVTags.java
https://github.com/sasc999/javaemvreader/blob/master/src/main/java/sasc/emv/system/mastercard/MCTags.java
https://github.com/sasc999/javaemvreader/blob/master/src/main/java/sasc/emv/system/visa/VISATags.java

Good list of AIDs: https://www.eftlab.com.au/index.php/site-map/knowledge-base/211-emv-aid-rid-pix

Good list of commands: http://www.wrankl.de/SCTables/SCTables.html

http://stackoverflow.com/a/23359247/37923

https://www.emvco.com/specifications.aspx?id=21

http://www.abc-smartcard.com/solutions/emv-l2-contactless-stack/
EMVco C-1 Kernel 1 V2.4 for some cards with JCB AIDs and some cards with Visa AIDs
EMVco C-2 Kernel 2 V2.4 for MasterCards AIDs
EMVco C-3 Kernel 3 V2.4 for Visa AIDs
EMVco C-4 Kernel 4 V2.4 for American Express AIDs
EMVco C-5 Kernel 5 V2.4 for JCB AIDs
EMVco C-6 Kernel 6 V2.4 for Discover AIDs
EMVco C-7 Kernel 7 V2.4 for UnionPay AIDs


http://rfidsec2015.iaik.tugraz.at/wp-content/uploads/2015/08/tut-Deruiter-slides.pdf (really good)
EMV mode
o No DDA
o Only one application cryptogram for online transactions
o Torn transactions can be restored using RECOVER AC
command
o Terminal can store data on card in 'scratch pad'

Visa payWave
o Kernel 1 and 3
o EMV modes (VSDC and qVSDC)
o Mag-stripe mode (MSD)
o VSDC uses original EMV with minor changes
o qVSDC quite different from original EMV
- Minimises number of messages
- fDDA
- No separate command for cryptogram generation
o No offline plaintext PIN allowed

from Kernel 3 2.1, EMV Mode features:
- An offline transaction flow for below floor limit transactions, with offline data authentication and a clearing cryptogram.
- An online transaction flow with online card authentication and an option for a second re-presentment of the card for issuer updating of card parameters.
- Cardholder verification support by means of online PIN or signature, when required by the transaction conditions.
- Support for consumer device form factors (e.g. mobile phones) acting as card products, including support for the Consumer Device CVM.

An accelerated offline data authentication method, fast Dynamic Data Authentication
(fDDA), is provided through use of the GPO command to initiate the dynamic
signature. A DDOL is not used and the results of the authentication are not provided
online to the issuer within the TVR or protected by the online authorisation or clearing
cryptograms.

...

During Pre-Processing, Entry Point will use the reader risk parameters, configured in
the EMV mode-enabled reader, to determine whether an EMV mode transaction with
an amount of zero will result in an online transaction (if passed to this kernel) or will
be conducted over another interface or passed to another kernel


Check out https://github.com/apuigsech/emv-framework

"""

Lc = {
0x0: 'Universal',
0x40: 'Application',
0x80: 'Context',
0xc0: 'Private',
}

# Parsers for BER
def raw(ber):
    return ber.data

def chunk(x, n):
    return [x[i:i + n] for i in range(0, len(x), n)]

def chunker(n):
    return lambda ber: chunk(ber.data, n)

def tag_length(ber):
    # For PDOL. Contains a requested length, not a value
    entries = []

    d = iter(ber.data)
    while True:
        try:
            tag = ber.read_tag_id(d)
            # No idea if this can be multi-byte
            length = int(d.next())
            entries.append((tag, length))
        except StopIteration:
            break

    return entries

def bcd(ber):
    return 

# TODO: make these into classes with __repr__s
# (as they really are classes/types, not functions)

def parse_app(ber):
    priority = ber.parsed('PRIORITY')
    label = ber.getparsed('APP_LABEL')
    aid = ber.parsed('AID')
    return (priority, label, aid)

def parse_track2(ber):
    track2 = ''.join(['%02X' % b for b in ber.data])
    cardnum, rest = track2.split('D', 1)
    expiry = rest[:4]
    service = rest[4:7]
    extra = rest[7:]

    track2 = dict(
        cardnum=cardnum,
        expiry=expiry,
        service=service,
        extra=extra,
    )
    return track2


def format_dfname(ber):
    if ber.data[0] & 0x80:
        return toHexString(ber.data)
    else:
        return str(ber)

class EMV(object):
    STATUSES = {
        0x90: 'OK',
        0x61: 'More data',
        0x62: 'No change',
        (0x62, 0x83): 'selected file invalidated',
        (0x62, 0x84): 'selected file incorrectly formatted',
        (0x62, 0x85): 'selected file in termination state',
        0x63: 'Changed',
        0x64: 'Error, no change',
        0x65: 'Error, changed',
        0x66: 'Security',
        0x67: 'Wrong length',
        0x68: 'Not supported',
        0x69: 'Not allowed',
        (0x69, 0x81): 'incompatible',
        (0x69, 0x82): 'security',
        (0x69, 0x83): 'authentication',
        (0x69, 0x84): 'invalid',
        (0x69, 0x85): 'conditions',
        (0x69, 0x86): 'not allowed',
        (0x69, 0x87): 'missing',
        (0x69, 0x88): 'incorrect',
        0x6a: 'Bad arguments',
        (0x6a, 0x80): 'data',
        (0x6a, 0x81): 'not supported',
        (0x6a, 0x82): 'file not found',
        (0x6a, 0x83): 'record not found',
        (0x6a, 0x84): 'no space',
        (0x6a, 0x85): 'bad structure',
        (0x6a, 0x86): 'P1/P2',
        (0x6a, 0x87): 'bad lengh',
        (0x6a, 0x88): 'not found',
        0x6b: 'Wrong arguments',
        0x6c: 'Wrong length',
        0x6d: 'Invalid',
        0x6e: 'Not supported',
        0x6f: 'Unknown',
    }

    TAGS = Tags(
        (0x4f,   'AID', raw),
        (0x50,   'APP_LABEL', str),
        (0x57,   'TRACK2', parse_track2),
        (0x5f20, 'NAME', str),
        (0x5f2d, 'LANG', str),
        (0x5f34, 'PSN', int),  # PAN sequence number
        (0x61,   'APP', parse_app),
        (0x6f,   'FCI'),
        (0x77,   'RMTF2'),
        (0x70,   'EMV'),
        (0x80,   'RMTF1', raw),
        (0x82,   'AIP', raw),  # Application interchange profile
        (0x84,   'DFNAME'),  # FIXME: create a DFName object
        (0x87,   'PRIORITY', int),
        (0x88,   'SFI', int),
        (0x90,   'OK'),
        (0x94,   'AFL', raw),  # Application file locator
        (0xa5,   'FCI_ISSUER'),
        (0x9f10, 'IAD', raw),  # Issuer application data
        (0x9f26, 'AC', raw),  # Application cryptogram
        (0x9f27, 'CID', raw),  # Cryptogram information data
        (0x9f17, 'PIN_TRIES', int),
        (0x9f36, 'ATC', int),
        (0x9f38, 'PDOL', tag_length),
        (0x9f4b, 'SDAD', raw),  # Signed dynamic application data
        (0x9f51, 'DRDOL', raw),
        (0x9f54, 'ODS', raw),
        (0x9f56, 'ISSUER_INFO', int),
        (0x9f57, 'ISSUER_COUNTRY', int),
        (0x9f5a, 'PROGRAM_ID'), # or terminal transaction type (interac)???
        (0x9f5e, 'DS_ID', int),
        # http://www.openscdp.org/scripts/tutorial/emv/cardholderverification.html
        (0x9f68, 'CVM', chunker(2)),
        # https://www.eftlab.com.au/index.php/site-map/our-articles/161-the-use-of-ctqs-and-ttqs-in-nfc-transactions
        (0x9f6c, 'CTQ', chunker(2)),
        # 080312 VSDC 281AM2 on mine
        (0x9f7d, 'APPLET_DATA', str),
        (0x9f7f, 'UN', raw),
        (0xbf0c, 'FCI_EXTRA'),
    )

    BER = BERWithTags(TAGS)

    def __init__(self, tag):
        self.tag = tag
        self.pin_tries = None

    def send(self, apdu):
        resp = self.tag.send(apdu)
        sw1, sw2 = resp[-2:]
        if (sw1, sw2) == (0x90, 0):
            return resp
        raise EMVException(sw1, sw2)

    def select_by_id(self, type=0, id=None):
        # Doesn't seem to work
        if id is None:
            id = [] # or [0x3f, 0]
        resp = self.send(APDU(0, 0xa4, 0, type & 3, data=id))
        return resp

    def select_by_df(self, pattern, which='first'):
        which = ['first', 'last', 'next', 'prev'].index(which)
        resp = self.send(APDU(0, 0xa4, 4, which, data=pattern))

        ber = self.BER(resp)
        fci = ber['FCI']
        fci_issuer = fci['FCI_ISSUER']

        # FIXME: this should be a class or dict
        df = format_dfname(fci['DFNAME'])
        sfi = fci_issuer.getparsed('SFI')
        pdol_req = fci_issuer.getparsed('PDOL')

        return df, sfi, pdol_req

    def select_all_by_df(self, name):
        dfs = []
        try:
            dfs.append(self.select_by_df(name))
            while True:
                dfs.append(self.select_by_df(name, 'next'))
        except EMVException, e:
            if not (e.sw1, e.sw2) == (0x6a, 0x82):
                raise

        return dfs

    def read_record(self, record, sfi=None, which='index'):
        if sfi is None:
            sfi = 0
        which = ['first', 'last', 'next', 'prev', 'index', 'indexfrom', 'indexto'].index(which)
        resp = self.send(APDU(0, 0xb2, record, (sfi << 3) + which))
        return resp

    def read_record_parsed(self, record, sfi=None, which='index'):
        data = self.read_record(record, sfi=sfi, which=which)
        ber = self.BER(data)
        return ber['EMV']

    def read_all_records(self, sfi):
        records = []
        for n in range(1, 0x7f):
            try:
                records.append(self.read_record(n, sfi))
            except EMVException, e:
                if not (e.sw1, e.sw2) == (0x6a, 0x83):
                    raise
                break

        return records

    def parse_card(self, data):
        card = self.BER(data)['EMV']

        vals = dict(
            name=card.parsed('NAME')
        )
        vals.update(card.parsed('TRACK2'))

        return vals

    def verify(self, pin):
        if self.pin_tries is None:
            self.get_pin_tries()

        print 'PIN tries left: %s' % self.pin_tries
        if not self.pin_tries:
            raise EMVError('No PIN retries left')

        assert pin.isdigit()

        pinhex = pin + 'f' * 14
        hexdata = '2%s' % len(pin) + pinhex[:14]
        resp = self.send(APDU(0, 0x20, 0x61, 0x80, data=toBytes(hexdata)))

        self.pin_tries = None
        return resp

    def get_challenge(self, length):
        resp = self.send(APDU(0, 0x84, data=[0] * length))
        return self.BER(resp)

    def get_data(self, tag):
        if isinstance(tag, basestring):
            tag = self.TAGS[tag]
        # Seems to work with either 0 or 0x80 for class
        resp = self.send(APDU(0x80, 0xca, tag >> 8, tag & 0xff))
        return resp

    def get_data_parsed(self, tag):
        data = self.get_data(tag)
        ber = self.BER(data)
        return ber.parsed(tag)

    def get_pin_tries(self):
        self.pin_tries = self.get_data_parsed('PIN_TRIES')
        return self.pin_tries

# Try putting 9F67, for an overflow

    def get_options(self, pdol_req, dol=None):
        if dol is None:
            dol = DOL()
        pdol = dol.get_dol(pdol_req)
        # FIXME: make the dol have a todata function which returns 0x83...
        resp = self.send(APDU(0x80, 0xa8, data=[0x83, len(pdol)] + pdol))
        return self.BER(resp)

    def generate_ac(self, type='aac'):
        #, cdol_req, data):
        # priority order is tc (transaction certificate), arqc (auth req), aac (app authentication - declined), aar
        p1 = ['aac', 'tc', 'arqc', 'aar'].index(type) * 0x40
        #cdol_req = [(0x9f6a, 0x04)]
        #cdol = self.create_dol(cdol_req)
        #cdol = [0, 0, 0, 0, 1, 0] + [0, 0, 0, 0, 0, 0] + [0x8, 0x26] + [0, 0, 0, 0] + [0x8, 0x26] + [0x10, 0x10, 0x10] + [0] + [0x12, 0x34, 0x56, 0x78]
        resp = self.send(APDU(0x80, 0xae, p1, data=cdol))
        return self.BER(resp)

    def external_auth(self):
        resp = self.send(APDU(0, 0x82))
        return self.BER(resp)

# Data Object List
class DOL(object):
    def __init__(self, ttq=None, ccy=None):
        self.ttq = [0x80 | 0x08 | 0x02, 0, 0, 0]
        self.ttq = [0x80 | 0x40 | 0x20 | 0x10 | 0x04 | 0x02, 0, 0, 0]
        self.ttq = [0xa6, 0x20, 0xc0, 0]
        if ttq is not None:
            self.ttq = ttq

        self.ccy = [0x08, 0x26] # GBP
        self.ccy = [0x08, 0x40] # USD
        self.ccy = [0x09, 0x63] # Testing
        self.ccy = [0x09, 0x99] # None
        self.ccy = [0x09, 0x78] # Euro
        # EUR or USD unlock 0x9f4b
        if ccy is not None:
            self.ccy = ccy

    def get_dol(self, dol_req=None):
        dol = []
        if dol_req is None:
            dol_req = []

        # a6 20 c0 00
        # 00 00 00 00 00 01 
        # 55 5d 77 41
        # 09 78
        for tag, length in dol_req:
            if (tag, length) == (0x9f66, 4):
                # TTQ - terminal transaction qualifier
                # Byte 1
                # +0x80 MSD (magstripe mode) contactless supported
                #  0x40 VSDC contactless supported (reserved in EMV)
                # +0x20 qVSDC (EMV mode) contactless supported
                # +0x10 VSDC (EMV) contact chip supported
                # +0x08 no online mode supported
                # +0x04 online PIN supported
                # +0x02 signature supported
                # +0x01 offline DA for online supported
                #
                # Byte 2
                # +0x80 online cryptogram required
                # +0x40 CVM required
                # +0x20 contact chip offline PIN supported
                #
                # Byte 3
                # +0x80 issuer update processing
                # +0x40 consumer device CVM
                #
                # All else reserved

                data = self.ttq

            elif (tag, length) == (0x9f02, 6):
                # Amount authorised
                data = [0, 0, 0, 0, 0, 0]

            elif tag == 0x9f37:
                # Unpredictable number
                data = map(ord, urandom(length))

            elif tag == 0x9f6a:
                # Unpredictable number
                data = map(ord, urandom(length))

            elif (tag, length) == (0x5f2a, 2):
                # Country code - http://en.wikipedia.org/wiki/ISO_4217
                data = self.ccy

            else:
                raise NotImplementedError('Cannot reply to PDOL tag %s with length %s' % (tag, length))

            assert len(data) == length
            dol += data

        return dol



if __name__ == '__main__':
    from rfid import Pcsc, AcsReader
    from pprint import pprint
    import sys

    with Pcsc.reader() as reader:

        # FIXME
        if isinstance(reader, AcsReader):
            tags = reader.pn532.scan()
        else:
            tags = [reader.tag]

        for tag in tags:

            # print tag.find_unique_id()


            # Why does 2PAY return an empty sfi?

            # not listed, but selectable - tag.emv.select_by_df([0xA0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0])

            # Use PSE to list apps
            #name, sfi, pdol_req = tag.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
            #name, sfi, pdol_req = tag.emv.select_by_df([0xa0, 0, 0, 0, 3, 0x10, 0x10])
            #print pdol_req
            # Use PPSE to list apps
            #name, sfi, pdol_req = tag.emv.select_by_df(toASCIIBytes('2PAY.SYS.DDF01'))
            #name, sfi, pdol_req = tag.emv.select_by_df([0xa0, 0, 0, 0, 3, 0x10, 0x10])
            #print pdol_req
            #options = tag.emv.get_options(pdol_req)
            #options.dump()
            #pprint(options.get_struct())
            #break


            if False:
                # Use PSE to list apps
                name, sfi, pdol_req = tag.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
                print 'Applet data: %s' % tag.emv.get_data_parsed('APPLET_DATA')

                data = tag.emv.read_record_parsed(0x1, sfi)
                data.dump()
                apps = data.getlistparsed('APP')

            else:
                apps = [(0, 'BARCLAYS', [0xa0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02])]  # Visa CAP


            for priority, name, aid in apps:
                print
                print 'Selecting %s (%s): %s' % (priority, name, toHexString(aid))
                name, sfi, pdol_req = tag.emv.select_by_df(aid)
                if pdol_req:
                    print 'PDOL request:'
                    for tag_id, length in pdol_req:
                        print '  0x%x: %s' % (tag_id, length)

                #print '%s: %s' % (toHexString(aid), toHexString(tag.emv.read_record(1, sfi)))

                if False:
                    sfi = 1 # FIXME: why is this None by default?
                    tag.emv.read_record_parsed(0x1, sfi).dump()
                    card = tag.emv.read_record_parsed(0x1, sfi)['TRACK2']
                    print card
                    #print card['cardnum']

                if False:
                    data = [
                        ('Applet data:    %s',   'APPLET_DATA'),
                        ('ATC:            %d',   'ATC'),
                        ('DRDOL:          %r',   'DRDOL'),
                        ('Issuer info:    0x%x', 'ISSUER_INFO'),
                        ('Issuer country: 0x%x', 'ISSUER_COUNTRY'),
                        ('DS ID:          %d',   'DS_ID'),
                        ('CVM:            %s',   'CVM'),
                        ('CTQ:            %s',   'CTQ'),
                    ]
                    for f, t in data:
                        print f % tag.emv.get_data_parsed(t)


                if True:
                    #print tag.emv.get_data_parsed('ATC')
                    # This increments the ATC
                    options = tag.emv.get_options(pdol_req)
                    # TODO: save this for next time so we don't need to increment ATC
                    #print tag.emv.get_data_parsed('ATC')

                    if 'RMTF1' in options:
                        options['RMTF1'].dump()
                        aip = options['RMTF1'].data[:2]
                        afl = options['RMTF1'].data[2:]
                        print 'AIP: %s' % aip
                        print 'AFL: %s' % afl

                        sfi = afl[0] >> 3
                        start, end, authrecords = afl[1:]

                    elif 'RMTF2' in options:
                        sfi, start, end, authrecords = options['RMTF2']['AFL'].data
                        aip = options['RMTF2']['AIP'].data

                    # FIXME
                    AIP_BYTE1 = [
                        (0x40, 'SDA supported'),
                        (0x20, 'DDA supported'),
                        (0x10, 'cardholder verification supported'),
                        (0x8, 'terminal risk management required'),
                        (0x4, 'issuer authentication supported'),
                        (0x2, 'on-device cardholder verification supported'),
                        (0x1, 'CDA supported'),
                    ]
                    AIP_BYTE2 = [
                        (0x80, 'EMV supported'),
                    ]

                else:
                    sfi, start, end, authrecords = 1, 1, 1, 0

                if False:
                    for i in range(0x40):
                        try:
                            print '%s: %s' % (i, tag.emv.get_challenge(i))
                            break
                        except Exception:
                            pass
                    else:
                        print 'No challenge length accepted'

                if authrecords > 0:
                    # follow process at http://www.openscdp.org/scripts/tutorial/emv/readapplicationdata.html
                    raise NotImplementedError()

                for i in range(start, end + 1):
                    data = tag.emv.read_record_parsed(i, sfi)
                    print data.dump()
                    extra = data.parsed('TRACK2')['extra']
                    assert extra[-1:] == 'F'  # padding
                    assert extra[-2:-1] == '1'  # ? is 0 for just-EMV mode
                    assert extra[:5] == '00000'  # pin verification field
                    thing = toBytes('0' + extra[5:-2])
                    print toHexString(thing)
                    # thing appears to be some sort of LSFR?

                    # For ttq of just 0x20, extra is 0000003771940f
                    # Does 1 mean magstripe mode?

                # NB this is the same as before, but extra is part randomised

                #print tag.emv.get_data(0x8e)
                #print tag.emv.get_challenge(0)
                #tag.emv.verify('0000')
                #tag.emv.generate_ac(0x40, [], thing)
                #tag.emv.external_auth()

                # 9f10 is mandatory, but isn't in any read records.
                cid = 0 # 5.4.3.1

                break # temporarily


from rfid import AcsReader, APDU
