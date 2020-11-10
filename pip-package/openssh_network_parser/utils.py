import os
import tabulate
import logging


def filesize(fileobj):
    current = fileobj.tell()
    fileobj.seek(0, 2)
    size = fileobj.tell()
    fileobj.seek(current, 0)
    return size


def get_unused_filepath(filepath):
    x = 1
    dir_path = os.path.dirname(filepath)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    new_filepath = filepath
    while os.path.exists(new_filepath):
        new_filepath = "{}.{}".format(filepath, x)
        x += 1
    return new_filepath


def peek(f, size):
    pos = f.tell()
    data = f.read(size)
    f.seek(pos)
    return data

def has_data(f):
    offset = f.tell()
    size = filesize(f)
    return offset < size


def util_repr(obj):
    cls = type(obj).__name__
    s = "{}".format(", ".join(["%s: %s\n" % (k, (v) if type(v) in (int, long) else repr(v)) for k, v in obj.__dict__.items()]))
    return s


def pretty_format_struct(struct, exclude_fields=None, value_callback=None):
    exclude_fields = exclude_fields or []
    data = []
    for k in struct._values:
        if k in exclude_fields:
            continue
        val = struct._values[k]
        if value_callback:
            val = value_callback(val)
        if isinstance(val, str):
            val = repr(val)
        key = "{}:".format(k)
        data.append([key, val])
    return tabulate.tabulate(data, tablefmt="plain")


def add_logging_level(level_name, level_num, method_name=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> add_logging_level('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError('{} already defined in logging module'.format(level_name))
    if hasattr(logging, method_name):
        raise AttributeError('{} already defined in logging module'.format(method_name))
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError('{} already defined in logger class'.format(method_name))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, **kwargs)

    def log_to_root(message, *args, **kwargs):
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)
