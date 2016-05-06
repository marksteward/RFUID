#!/usr/bin/env python
from smartcard.util import toASCIIBytes, toHexString
#from hashlib import sha256
from common import TagException
from collections import defaultdict

class TagInstructionNotSupported(TagException):
    pass

class CardID(str):
    pass

class CardUID(CardID):
    # Not very unique, as can be randomised 
    # or fixed (e.g. 21222324)
    pass

class CardHashedUN(CardID):
    # Appears to be reasonably unique, but
    # can still be fixed or have low entropy
    pass


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

    # TODO: differentiate a reader from the tag perspective from a host controller
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

    def find_unique_id(self):
        # when registering a card, the caller should always
        # power cycle and try again to detect randomised IDs

        if self.uid == '21222324':

            un = self.emv.get_data_parsed('UN')
            digits = defaultdict(int)
            for digit in un:
                digits[digit] += 1

            if len(digits) > 5:
                # Assume there's enough entropy to hash safely
                # Don't return the actual UN, as that needs to
                # remain unpredictable
                #return CardHashedUN(hashlib.sha256(un))
                return CardHashedUN(' '.join('%02x' % x for x in un))

            #name, sfi = self.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
            #apps = self.emv.parse_apps(self.emv.read_record(1, sfi))
            #priority, name, aid = apps[0]
            #self.emv.select_by_df(aid)

            # don't return cardnum because that can be used for offline fraud
            #card = self.emv.parse_card(self.emv.read_record(1, sfi))
            #return card['cardnum']

        else:
            return CardUID(self.uid)


from emv import EMV

if __name__ == '__main__':
    from rfid import Pcsc
    from pprint import pprint

    with Pcsc.reader() as reader:
        for tag in reader.pn532.scan():

            print tag.find_unique_id()

