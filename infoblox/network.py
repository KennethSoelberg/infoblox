from collections import OrderedDict
import tablib


class Network:

    __slots__ = ('_keys', '_values')

    def __init__(self, keys, values):
        # Rename _ref to ref
        self._keys = [key if key != '_ref' else 'ref' for key in keys]
        self._values = values

        # Ensure that lengths match properly.
        assert len(self._keys) == len(self._values)

    def keys(self):
        """Returns the list of column names from the query."""
        return self._keys

    def values(self):
        """Returns the list of values from the query."""
        return self._values

    def __repr__(self):
        return f'<Network {self.export("json")[1:-1]}>'

    def __getitem__(self, key):
        # Support for index-based lookup.
        if isinstance(key, int):
            return self.values()[key]

        # Support for string-based lookup.
        if key in self.keys():
            i = self.keys().index(key)
            if self.keys().count(key) > 1:
                raise KeyError(f"Network contains multiple '{key}' fields.")
            return self.values()[i]

        raise KeyError(f"Network contains no '{key}' field.")

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as e:
            raise AttributeError(e)

    def __dir__(self):
        standard = dir(super(Network, self))
        # Merge standard attrs with generated ones (from column names).
        return sorted(standard + [str(k) for k in self.keys()])

    def get(self, key, default=None):
        """Returns the value for a given key, or default."""
        try:
            return self[key]
        except KeyError:
            return default

    def as_dict(self, ordered=False):
        """Returns the row as a dictionary, as ordered."""
        items = zip(self.keys(), self.values())

        return OrderedDict(items) if ordered else dict(items)

    @property
    def dataset(self):
        """A Tablib Dataset containing the row."""
        data = tablib.Dataset()
        data.headers = self.keys()
        data.append(self.values())

        return data

    def export(self, export_format, **kwargs):
        """Exports the row to the given format."""
        return self.dataset.export(export_format, **kwargs)

