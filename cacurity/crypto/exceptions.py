class NoStartLine(Exception):
    """
    Indicates that we tried to load something from a pem, but there was no
    start line in the provided data for the object we were trying to load.
    """
    pass
