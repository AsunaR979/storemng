import sys
import six


def safe_decode(text, incoming=None, errors='strict'):
    """Decodes incoming text/bytes string using `incoming` if they're not
       already unicode.

    :param incoming: Text's current encoding
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a unicode `incoming` encoded
                representation of it.
    :raises TypeError: If text is not an instance of str
    """
    if not isinstance(text, (six.string_types, six.binary_type)):
        raise TypeError("%s can't be decoded" % type(text))

    if isinstance(text, six.text_type):
        return text

    if not incoming:
        incoming = (getattr(sys.stdin, 'encoding', None) or
                    sys.getdefaultencoding())

    try:
        return text.decode(incoming, errors)
    except UnicodeDecodeError:
        # Note(flaper87) If we get here, it means that
        # sys.stdin.encoding / sys.getdefaultencoding
        # didn't return a suitable encoding to decode
        # text. This happens mostly when global LANG
        # var is not set correctly and there's no
        # default encoding. In this case, most likely
        # python will use ASCII or ANSI encoders as
        # default encodings but they won't be capable
        # of decoding non-ASCII characters.
        #
        # Also, UTF-8 is being used since it's an ASCII
        # extension.
        return text.decode('utf-8', errors)


def safe_encode(text, incoming=None,
                encoding='utf-8', errors='strict'):
    """Encodes incoming text/bytes string using `encoding`.

    If incoming is not specified, text is expected to be encoded with
    current python's default encoding. (`sys.getdefaultencoding`)

    :param incoming: Text's current encoding
    :param encoding: Expected encoding for text (Default UTF-8)
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a bytestring `encoding` encoded
                representation of it.
    :raises TypeError: If text is not an instance of str

    See also to_utf8() function which is simpler and don't depend on
    the locale encoding.
    """
    if not isinstance(text, (six.string_types, six.binary_type)):
        raise TypeError("%s can't be encoded" % type(text))

    if not incoming:
        incoming = (getattr(sys.stdin, 'encoding', None) or
                    sys.getdefaultencoding())

    # Avoid case issues in comparisons
    if hasattr(incoming, 'lower'):
        incoming = incoming.lower()
    if hasattr(encoding, 'lower'):
        encoding = encoding.lower()

    if isinstance(text, six.text_type):
        return text.encode(encoding, errors)
    elif text and encoding != incoming:
        # Decode text before encoding it with `encoding`
        text = safe_decode(text, incoming, errors)
        return text.encode(encoding, errors)
    else:
        return text

def to_utf8(text):
    """Encode Unicode to UTF-8, return bytes unchanged.

    Raise TypeError if text is not a bytes string or a Unicode string.

    .. versionadded:: 3.5
    """
    if isinstance(text, six.binary_type):
        return text
    elif isinstance(text, six.text_type):
        return text.encode('utf-8')
    else:
        raise TypeError("bytes or Unicode expected, got %s"
                        % type(text).__name__)


def import_module(import_str):
    """Import a module.

    .. versionadded:: 0.3
    """
    __import__(import_str)
    return sys.modules[import_str]


def try_import(import_str, default=None):
    """Try to import a module and if it fails return default."""
    try:
        return import_module(import_str)
    except ImportError:
        return default
