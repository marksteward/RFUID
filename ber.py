#!/usr/bin/env python
from collections import defaultdict
from UserDict import DictMixin
import pprint

class Tags(object):
    default_parser = repr

    def __init__(self, *tagdata):
        self._tagdata = tagdata

        self.tags = {}
        self.tagnames = {}
        self.parsers = {}

        # tagdata is a list of id, name and optional parser
        for tag in tagdata:
            if len(tag) > 2:
                id, name, parser = tag
                self.parsers[id] = parser
            else:
                id, name = tag

            self.tags[name] = id
            self.tagnames[id] = name

    def __getitem__(self, name):
        return self.tags[name]

    def tagname(self, tag):
        return self.tagnames.get(tag, '0x%x' % tag)

    def tag(self, tag):
        return self[tag]

    def parser(self, tag, default=default_parser):
        return self.parsers.get(tag, default)


universal_tags = Tags(
    (0x1, 'BOOLEAN', bool),
    (0x2, 'INTEGER', int),
    (0x4, 'BYTES',   bytearray),
    (0x9, 'FLOAT',   float),
    (0xc, 'STRING',  str),
)
# everything else is repr

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
        self._entries = None
        if tags is not None:
            self.tags = tags
        else:
            self.tags = universal_tags

    def __hex__(self):
        return ' '.join('%02x' % b for b in self._data)

    def __repr__(self):
        return '<BER %s>' % hex(self)

    def __nonzero__(self):
        # No need to parse - any valid data will result in a tag
        # Invalid data will result in an exception when parsing
        return bool(self._data)


    # BER-specific stuff, to save time

    def __int__(self):
        return int(''.join('%02x' % b for b in self._data), 16)

    def __str__(self):
        return ''.join(map(chr, self._data))


    def bool(self, index=0):
        vals = self.ber[self.tags['BOOLEAN']]
        return bool(int(vals[index]))

    def int(self, index=0):
        vals = self.ber[self.tags['INTEGER']]
        return int(vals[index])

    def bytearray(self, index=0):
        vals = self.ber[self.tags['BYTES']]
        return bytearray(vals[index].data)

    def float(self, index=0):
        raise NotImplementedError()

    def str(self, index=0):
        vals = self.ber[self.tags['STRING']]
        return str(vals[index])


   # And now the MultiDict parts

    def __getitem__(self, tag):
        if isinstance(tag, basestring):
            tag = self.tags[tag]
        return self.ber[tag][0]

    def parsed(self, tag):
        if isinstance(tag, basestring):
            tag = self.tags[tag]
        parser = self.tags.parser(tag)
        return parser(self.ber[tag][0])

    def getparsed(self, tag, default=None):
        if isinstance(tag, basestring):
            tag = self.tags[tag]
        if tag not in self.ber:
            return default
        parser = self.tags.parser(tag)
        return parser(self.ber[tag][0])

    def getlist(self, tag):
        if isinstance(tag, basestring):
            tag = self.tags[tag]
        return self.ber.get(tag, [])

    def getlistparsed(self, tag):
        if isinstance(tag, basestring):
            tag = self.tags[tag]
        parser = self.tags.parser(tag)
        return map(parser, self.ber.get(tag, []))

    def keys(self):
        return self.ber.keys()

    def items(self):
        return [(k, v[0]) for k, v in self.ber]

    def values(self):
        return [v[0] for v in self.ber.values()]

    def lists(self):
        return self.ber.items()

    # FIXME: make lists return in order, or add an orderedlists?

    def listvalues(self):
        return self.ber.values()

    def to_dict(self):
        return dict(self.lists())


    @property
    def data(self):
        return self._data[:]

    @property
    def entries(self):
        if self._entries is None:
            self.read_ber()
        return self._entries

    @property
    def ber(self):
        if self._entries is None:
            self.read_ber()
            # Don't use a defaultdict, so we get KeyErrors
            self._ber = {}
            for tag, entry in self._entries:
                if tag not in self._ber:
                    self._ber[tag] = []
                self._ber[tag].append(entry)

        return self._ber

    def read_tag_id(self, d):
        tag = d.next()
        try:
            if tag & 0x1f == 0x1f:
                b = 0x80
                while b & 0x80:
                    b = d.next()
                    if not b & 0x7f:
                        raise ValueError('Invalid tag ID')
                    tag = (tag << 8) + (b & 0x7f)

            return tag

        except StopIteration:
            raise IndexError('Incomplete tag ID')
       
 
    def read_ber(self):
        d = iter(self._data)

        self._entries = []
        while True:
            try:
                tag = self.read_tag_id(d)
            except StopIteration:
                break

            try:
                length = d.next()
                if length & 0x80:
                    # size of the length field
                    size = length & 0x7f
                    if size == 0:
                        # read up to EOC tag
                        raise NotImplementedError('Indefinite length')

                    length = 0
                    for i in range(size):
                        length = (length << 8) + d.next()

                value = [d.next() for i in range(length)]

                # This shouldn't be needed for consuming,
                # but it's helpful for debugging
                self._entries.append((tag, BER(value, tags=self.tags)))

            except StopIteration, e:
                raise EOFError('Incomplete data')



    def get_struct(self):
        entries = []
        
        if self._entries is None:
            self.read_ber()

        for tag, entry in self._entries:
            parser = self.tags.parser(tag, None)
            if parser:
                pass
            elif entry.data:
                try:
                    entry.read_ber()
                except Exception, e:
                    pass
                else:
                    entry = entry.get_struct()

            entries.append((tag, entry))

        return entries

    # FIXME: consider flattening it first (with a depth and tag for each line), so it can be post-processed

    def dump_ber(self, depth=0):
        last_tag = None
        lines = []

        def indent(line, depth):
            return '  ' * depth + line

        if self._entries is None:
            self.read_ber()

        for tag, entry in self._entries:
            if tag != last_tag:
                if tag in self.tags.tagnames:
                    tagstr = '%s (0x%x)' % (self.tags.tagname(tag), tag)
                else:
                    tagstr = '0x%x' % tag
                lines.append(indent(tagstr, depth))

            parser = self.tags.parser(tag, None)
            if parser:
                entry = repr(parser(entry))
            elif entry.data:
                try:
                    entry.read_ber()
                except Exception, e:
                    entry = repr(entry)
                else:
                    entry = entry.dump_ber(depth=depth + 1)
            else:
                entry = ''

            lines.append(indent(entry, depth + 1))
            last_tag = tag

        return '\n'.join(lines)

    def dump(self):
        print self.dump_ber()


def BERWithTags(tags):
    tags = Tags(*universal_tags._tagdata + tags._tagdata)
    class BERWithTags(BER):
        def __init__(self, data):
            BER.__init__(self, data, tags=tags)
    return BERWithTags


if __name__ == '__main__':
    import doctest
    doctest.testmod()

