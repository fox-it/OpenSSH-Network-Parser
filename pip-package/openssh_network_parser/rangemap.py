from bisect import bisect_left
from collections import Mapping


class RangeLookupTable(Mapping):
    """A lookup table with contiguous ranges of small positive integers as
    keys. Initialize a table by passing pairs (max, value) as
    arguments. The first range starts at 1, and second and subsequent
    ranges start at the end of the previous range.

    >>> t = LookupTable((10, '1-10'), (35, '11-35'), (100, '36-100'))
    >>> t[10], t[11], t[100]
    ('1-10', '11-35', '36-100')
    >>> t[0]
    Traceback (most recent call last):
      ...
    KeyError: 0
    >>> next(iter(t.items()))
    (1, '1-10')

    """
    def __init__(self, *args):
        self.table = list(args)
        #self.max = 0

    @property
    def max(self):
        if len(self.table) == 0:
            return None
        return self.table[-1][0]

    def append(self, m, value):
        self.table.append((m, value))

    def in_range(self, key):
        if len(self.table) == 0:
            return False
        return 0 <= key <= self.max

    def get(self, key):
        key = int(key)
        if not self.in_range(key):
            return None
        return self[key]

    def __getitem__(self, key):
        key = int(key)
        if not self.in_range(key):
            raise KeyError(key)
        return self.table[bisect_left(self.table, (key,))][1]

    def __iter__(self):
        return iter([i[0] for i in self.table])

    def __len__(self):
        return self.max


def main():
    t = RangeLookupTable((24, '0-25'), (99, '25-100'), (120, '100-120'))
    t = RangeLookupTable()
    # print t.table
    print t[0]
    print t[24]
    print t[25]

    print t[26]
    print t[99]
    print t[100]

if __name__ == "__main__":
    main()
