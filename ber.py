#!/usr/bin/env python
from collections import defaultdict
from UserDict import DictMixin

universal_tags = dict(
    BOOLEAN    = 0x1,
    INTEGER    = 0x2,
    BYTES      = 0x4,
    FLOAT      = 0x9,
    STRING     = 0xc,
)

class BER(DictMixin):
    """
    These are ASN.1 TLV records
    http://en.wikipedia.org/wiki/X.690

    >>> ber1 = BER([0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21])
    >>> ber2 = BER([0x30, 0x0a, 0x02, 0x01, 0x1e,
    ...                         0x02, 0x02, 0xc3, 0x50,
    ...                         0x01, 0x01, 0x00])

    A BER is just a sequence of bytes, whose meaning is determined
    by its record type (tag) in a hierarchical context.
    
    >>> ber1
    <BER 0c 06 48 65 6c 6c 6f 21>
    >>> ber2
    <BER 30 0a 02 01 1e 02 02 c3 50 01 01 00>

    To avoid reproducing an entire spec - as pyasn1 would require -
    we rely on the caller to tell us what children it expects.

    Index a BER by tag number (or name), and you get back the first
    matching child record. A complex type usually looks the same as
    a sequence (tag 0x30).

    >>> ber1['STRING']
    <BER 48 65 6c 6c 6f 21>
    >>> seq = ber2[0x30]
    >>> seq
    <BER 02 01 1e 02 02 c3 50 01 01 00>

    Call getlist if you expect more than one matching child.

    >>> seq.getlist('INTEGER')
    [<BER 1e>, <BER c3 50>]

    >>> seq.getlist('FLOAT')
    []

    Call int or str and we coerce it to that type, even if it's not correct.

    >>> str(ber1['STRING'])
    'Hello!'

    >>> map(int, seq.getlist('INTEGER'))
    [30, 50000]

    For universal types, there are helpers that do the coercing for you.

    >>> seq.int(1)
    50000

    >>> seq.bool()
    False

    Use .data for a copy of the underlying sequence of bytes.

    >>> seq['BOOLEAN'].data
    [0]

    Use other dict functions to determine available records, and call
    .lists for a list of tags and corresponding records.

    >>> sorted(seq.keys())
    [1, 2]
    >>> 'BOOLEAN' in seq
    True
    >>> sorted(seq.lists())
    [(1, [<BER 00>]), (2, [<BER 1e>, <BER c3 50>])]

    Initialise with a dict of tags to add to the well-known ones.

    >>> label = BER([0x50, 0x1, 0x41], tags={'LABEL': 0x50})
    >>> str(label['LABEL'])
    'A'
    """

    def __init__(self, data, tags=None):
        self._data = data
        self._ber = None
        if tags is not None:
            self.tags = tags
        else:
            self.tags = {}


    def __repr__(self):
        return '<BER %s>' % ' '.join('%02x' % b for b in self._data)

    def __nonzero__(self):
        if self._ber is None:
            # No need to parse
            return bool(self._data)
        return bool(self._ber)


    # BER-specific stuff, to save time

    def __int__(self):
        return int(''.join('%02x' % b for b in self._data), 16)

    def __str__(self):
        return ''.join(map(chr, self._data))


    def bool(self, index=0):
        vals = self.ber[self.gettag('BOOLEAN')]
        return bool(int(vals[index]))

    def int(self, index=0):
        vals = self.ber[self.gettag('INTEGER')]
        return int(vals[index])

    def bytearray(self, index=0):
        vals = self.ber[self.gettag('BYTES')]
        return bytearray(vals[index].data)

    def float(self, index=0):
        raise NotImplementedError()

    def str(self, index=0):
        vals = self.ber[self.gettag('STRING')]
        return str(vals[index])

    def gettag(self, tag):
        try:
            return self.tags[tag]
        except KeyError, e:
            return universal_tags[tag]


   # And now the MultiDict parts

    def __getitem__(self, tag):
        if isinstance(tag, basestring):
            tag = self.gettag(tag)
        return self.ber[tag][0]

    def getlist(self, tag):
        if isinstance(tag, basestring):
            tag = self.gettag(tag)
        return self.ber.get(tag, [])

    def keys(self):
        return self.ber.keys()

    def items(self):
        return [(k, v[0]) for k, v in self.ber]

    def values(self):
        return [v[0] for v in self.ber.values()]

    def lists(self):
        return self.ber.items()

    def listvalues(self):
        return self.ber.values()

    def to_dict(self):
        return dict(self.lists())


    @property
    def data(self):
        return self._data[:]

    @property
    def ber(self):
        if self._ber is None:
            self.read_ber()
        return self._ber

 
    def read_ber(self):
        d = iter(self._data)

        rv = defaultdict(list)
        while True:
            try:
                tag = d.next()
            except StopIteration:
                break

            try:
                # Don't decode tagId, treat it as just a tag
                if tag & 0x1f == 0x1f:
                    t = 0x80
                    while t & 0x80:
                        t = d.next()
                        if not t & 0x7f:
                            raise ValueError()
                        tag = (tag << 8) + (t & 0x7f)

                length = d.next()
                if length & 0x80:
                    size = length & 0x7f
                    if size == 0:
                        raise NotImplementedError

                    length = 0
                    for i in range(size):
                        length = length << 8 + d.next()

                value = [d.next() for i in range(length)]

                rv[tag].append(BER(value, tags=self.tags))

            except StopIteration, e:
                raise IndexError()

        self._ber = dict(rv.items())


if __name__ == '__main__':
    import doctest
    doctest.testmod()

