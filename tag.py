#!/usr/bin/env python
from smartcard.util import toHexString, toASCIIString, toASCIIBytes
from smartcard.Exceptions import SmartcardException, NoReadersException, CardConnectionException, NoCardException
from ber import BER

class TagException(SmartcardException):
    pass

class TagInstructionNotSupported(TagException):
    pass

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
https://www.paypass.com/Term_TA/PP_Test_Cases_L2_%20Oct_10.pdf

"""


class Tag(object):
    SEL_RES = {
        0x00: 'Mifare Ultra',
        0x08: 'Mifare 1k',
        0x09: 'Mifare Mini',
        0x18: 'Mifare 4k',
        0x20: 'Mifare DESFire',
        0x28: 'JCOP30',
        0x98: 'Gemplus MPCOS',
    }

    # I need to differentiate a reader from the tag perspective from a host controller
    def __init__(self, reader, id, sens_res, sel_res):
        self.reader = reader
        self.id = id
        self.sens_res = sens_res
        self.sel_res = sel_res
        self.type = self.SEL_RES.get(sel_res, 'Unknown tag')
        self.uid = None
        self.ats = None
        self.emv = EMV(self)

    def __str__(self):
        return '<%s tag (%s)>' % (self.type, self.id)


    def send(self, apdu):
        return self.reader.send_to_tag(self.id, apdu)

    def find_14443_instrs(self):
        instrs = []
        for i in range(0xff):
            resp = self.send(APDU(0, i))
            if resp != [0x6d, 0]:
                instrs.append(i)

        return instrs

    def find_unique_id(self):
        # caller should power cycle and try again to detect randomised IDs
        if self.uid == '21222324':
            name, sfi = self.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
            apps = self.emv.parse_apps(self.emv.read_record(1, sfi))
            priority, name, aid = apps[0]
            self.emv.select_by_df(aid)
            card = self.emv.parse_card(self.emv.read_record(1, sfi))
            return card['cardnum']

        else:
            return self.uid


class EMV(object):
    STATUSES = {
        0x90: 'OK',
        0x61: 'More data',
        0x62: 'No change',
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

    TAGS = dict(
        AID        = 0x4f,
        APP_LABEL  = 0x50,
        TRACK2     = 0x57,
        NAME       = 0x5f20,
        LANG       = 0x5f2d,
        APP        = 0x61,
        FCI        = 0x6f,
        EMV        = 0x70,
        DFNAME     = 0x84,
        PRIORITY   = 0x87,
        SFI        = 0x88,
        FCI_PROP   = 0xa5,
        FCI_OPT    = 0xbf0c,
    )

    def __init__(self, tag):
        self.tag = tag

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

        ber = BER(resp, tags=EMV.TAGS)
        fci = ber['FCI']

        df = str(fci['DFNAME'])

        fci_issuer = fci['FCI_PROP']
        sfi = None
        if 'SFI' in fci_issuer:
            sfi = int(fci_issuer['SFI'])

        #lang = str(fci_issuer['LANG'])

        return df, sfi

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
        
    def parse_apps(self, resp):
        ber = BER(resp, tags=EMV.TAGS)
        emv = ber['EMV']
        apps = []

        for app in emv.getlist('APP'):
            priority = int(app['PRIORITY'])
            label = str(app['APP_LABEL'])
            aid = app['AID'].data
            apps.append((priority, label, aid))

        return sorted(apps)

    def parse_card(self, data):
        card = BER(data, tags=EMV.TAGS)['EMV']

        name = str(card['NAME'])
        track2 = card['TRACK2'].data

        track2 = ''.join(['%02X' % b for b in track2])
        cardnum, rest = track2.split('D', 1)
        expiry = rest[:4]
        service = rest[4:7]
        rest = rest[7:]

        card = dict(
            name = name,
            cardnum = cardnum,
            expiry = expiry,
            service = service,
            rest = rest,
        )
        return card


    def verify(self):
        resp = self.send(APDU(0, 0x20, 0, 0))
        return resp

    def get_data(self, val):
        resp = self.send(APDU(0, 0xca, val >> 8, val & 0xff))
        return resp



from rfid import Pcsc, APDU

if __name__ == '__main__':
    from pprint import pprint

    with Pcsc.reader() as reader:
        for tag in reader.pn532.scan():

            #print tag.find_unique_id()
            #continue


            emv = tag.emv
            # print map(hex, tag.find_14443_instrs())
            # 70, a4, ca

            #for variant in (1, 2):
            #    print emv.select_all_by_df('%dPAY.' % variant)

            def find_files(emv):
                for i in range(256):
                    try:
                        name, sfi = emv.select_by_df(toASCIIBytes(chr(i)))
                        print name, sfi

                    except Exception, e:
                        if isinstance(e, EMVException):
                            print e.sw1, e.sw2
                            if (e.sw1, e.sw2) == (0x6a, 0x82):
                                pass
                        else:
                            raise

            #find_files(emv)

            name, sfi = emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
            # print map(hex, tag.find_14443_instrs())
            # 70, a4, b2

            apps = emv.parse_apps(emv.read_record(1, sfi))

            pprint(apps)
            for priority, name, aid in apps:
                if name.startswith('VISA'):
                    emv.select_by_df(aid)
                    # print map(hex, tag.find_14443_instrs())
                    # 20, 70, 82, 84, 88, a4, b2

                    print emv.parse_card(emv.read_record(1, sfi))


