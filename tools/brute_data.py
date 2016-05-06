from tag import APDU, EMVException
from rfid import Pcsc, APDU
from smartcard.util import toHexString, toASCIIString, toASCIIBytes

def brute_data(tag):
    vals = []
    for i in range(0x10000):
        try:
            data = tag.emv.get_data(i)
        except EMVException, e:
            if not (e.sw1, e.sw2) in [(0x6a, 0x81), (0x6a, 0x88), (0x6d, 0x0)]:
                raise
        else:
            vals.append(i)

    print 'Accepted keys: %s' % ', '.join(map(hex, vals))

    # Nothing selected: 0x42, 0x45, 0x66, 0xc1, 0xc5, 0xc6, 0xc7, 0xcb, 0xcf, 0xe0, 0x9f7f, 0xdf7c, 0xdf7e
    # 1PAY.SYS.DDF01: 0x9f7d
    # LINK/VISADEBIT: 
    #   0x9f13, 0x9f17, 0x9f36, 0x9f51,
    #   0x9f52, 0x9f53, 0x9f54, 0x9f56,
    #   0x9f57, 0x9f58, 0x9f59, 0x9f5c,
    #   0x9f5e, 0x9f67, 0x9f68, 0x9f6c,
    #   0x9f6d, 0x9f72, 0x9f73, 0x9f77,
    #   0x9f78, 0x9f79, 0x9f7d, 0xbf55,
    #   0xbf56, 0xbf57, 0xbf58, 0xbf5b

with Pcsc.reader() as reader:
    for tag in reader.pn532.scan():
        brute_data(tag)

        print 'Selecting 1PAY'
        name, sfi = tag.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
        brute_data(tag)

        apps = tag.emv.parse_apps(tag.emv.read_record(0x1, sfi))

        for priority, name, aid in apps:
            print 'Selecting %s' % name
            tag.emv.select_by_df(aid)
            brute_data(tag)


