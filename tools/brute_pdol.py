from rfid import Pcsc, APDU
from ber import Tags
from emv import EMVException, DOL
from smartcard.util import toHexString, toASCIIString, toASCIIBytes
from collections import defaultdict

"""
For my card, which I bricked, I tried 0x2000 * 5 = 0xa000
ATC went from 0x978 to 0x7fff. Don't know whether there was a lower limit, though.
I seemed to get meaningful responses for all, but when I reconnected, I got "selected file invalidated".

ccys = [
    ([0x08, 0x26], 'GBP'),
    ([0x08, 0x40], 'USD'),
    ([0x09, 0x63], 'Testing'),
    ([0x09, 0x99], 'No currency'),
    ([0x09, 0x78], 'Euro'),
]
"""


def brute_pdol(tag):
    name, sfi, pdol_req = tag.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
    apps = tag.emv.read_record_parsed(1, sfi).getlistparsed('APP')
    for priority, name, aid in apps:
        ccy_ttq_dict = defaultdict(list)
        option_dict = defaultdict(list)
        not_allowed = []
        invalid = []

        try:
            name, sfi, pdol_req = tag.emv.select_by_df(aid)
            print 'ATC at start: %s' % tag.emv.get_data_parsed('ATC')

            # 12 bits
            for ttq in range(0x2000):
                if (ttq % 0x100) == 0:
                    print 'TTQ = 0x%lx' % ttq

                for ccy, ccy_name in ccys:
                    dol = DOL(ttq=[ttq & 0xff, ttq & 0x700 >> 3, ttq & 0x1800 >> 5, 0], ccy=ccy)
                    try:
                        # ATC is incremented if this works
                        options = tag.emv.get_options(pdol_req, dol)
                    except EMVException, e:
                        if (e.sw1, e.sw2) == (0x69, 0x85):
                            # Not allowed (conditions)
                            not_allowed.append((ttq, ccy_name))
                        elif (e.sw1, e.sw2) == (0x69, 0x84):
                            # Not allowed (invalid)
                            invalid.append((ttq, ccy_name))
                            # Reset
                            name, sfi, pdol_req = tag.emv.select_by_df(aid)
                        else:
                            raise
                    else:
                        ac_lens = tuple([len(a.data) for a in options.getlist('AC')])
                        sdad_lens = tuple([len(s.data) for s in options.getlist('SDAD')])

                        # replace AC, SDAD and ATC with length functions
                        options.tags = Tags(*options.tags._tagdata[:])
                        def datalen(ber):
                            return len(ber.data)

                        options.tags.parsers[options.tags.tags['AC']] = datalen
                        options.tags.parsers[options.tags.tags['SDAD']] = datalen
                        options.tags.parsers[options.tags.tags['ATC']] = datalen
                        options.read_ber()
                        opts = options.dump_ber()

                        #opts = [(k, vs) for k, vs in options.lists() if options.tags.tagname(k) not in ['AC', 'SDAD', 'ATC']]
                        # Need to be able to create a ber, or __delitem__
                        # FIXME: make dump return a string or an iterator
                        #opts = ' '.join(['0x%x %s' % (k, ', '.join([repr(v) for v in vs])) for k, vs in opts])
                        # opts = tuple([(k, tuple([tuple(v.data) for v in vs])) for k, vs in opts])
                        key = (opts, ac_lens, sdad_lens)
                        ccy_ttq_dict[key].append((ttq, ccy_name))
                        # only keep the last
                        option_dict[key] = options

                        # Reset to Entry Point Start C, according to Figure 5-1: Initiate Application Processing (Reader)
                        #  FIXME: check what Entry Point Start C is
                        name, sfi, pdol_req = tag.emv.select_by_df(aid)

        finally:
            def dump_ccy_ttqs(ccy_ttqs):
                last_ccy_name = None
                line = []
                for ttq, ccy_name in ccy_ttqs:
                    if last_ccy_name is not None and ccy_order.index(ccy_name) < ccy_order.index(last_ccy_name):
                        print '    %s' % ', '.join(line)
                        line = []
                    line.append('0x%x %s' % (ttq, ccy_name))
                    last_ccy_name = ccy_name

                if line:
                    print '    %s' % ', '.join(line)

            print 'ATC at end: %s' % tag.emv.get_data_parsed('ATC')

            ccy_order = [v for k, v in ccys]
            for key, ccy_ttqs in ccy_ttq_dict.items():
                print 'For:'
                dump_ccy_ttqs(ccy_ttqs)

                print
                option_dict[key].dump()

            print
            print 'Invalid:'
            dump_ccy_ttqs(invalid)

        break

if __name__ == '__main__':
    with Pcsc.reader() as reader:
        for tag in reader.pn532.scan():
            brute_pdol(tag)

