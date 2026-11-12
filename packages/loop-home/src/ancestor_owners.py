"""UID-map foundation for host and namespace readers; caller migration is separate."""
import ctypes
import os


class AncestorOwners:
    """Resolve inode UIDs through one kernel map snapshot per rubric read."""
    def __init__(self, source, owner, overflow):
        self.ranges = []
        limit = 2**32 - 1
        if not 0 <= overflow < limit:
            raise ValueError('ancestor uid_map invalid')
        for line in source.splitlines():
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) != 3 or any(not word.isascii() or not word.isdecimal() for word in fields):
                raise ValueError('ancestor uid_map invalid')
            inside, outside, count = map(int, fields)
            if (count == 0 or inside + count > limit or outside + count > limit
                    or any((inside < old_in + old_count and old_in < inside + count)
                           or (outside < old_out + old_count and old_out < outside + count)
                           for old_in, old_out, old_count in self.ranges)):
                raise ValueError('ancestor uid_map invalid')
            self.ranges.append((inside, outside, count))
        if not self.ranges:
            raise ValueError('ancestor uid_map invalid')
        self.owner = owner
        self.overflow = overflow
        self.complete = sum(row[2] for row in self.ranges) == limit
        self.parent_uid(owner)

    @classmethod
    def current(cls, owner):
        root = os.open('/proc', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            def verified(fd):
                library = ctypes.CDLL(None, use_errno=True)
                library.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
                library.fstatfs.restype = ctypes.c_int
                storage = (ctypes.c_long * 64)()
                if library.fstatfs(fd, ctypes.byref(storage)) != 0:
                    raise OSError(ctypes.get_errno(), 'ancestor procfs inspection')
                if storage[0] != 0x9fa0:
                    raise ValueError('ancestor metadata is not procfs')
            verified(root)
            def read(name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                with os.fdopen(fd, encoding='ascii') as source:
                    verified(source.fileno())
                    text = source.read(65537)
                    if len(text) > 65536:
                        raise ValueError('ancestor metadata exceeds bound')
                    return text
            return cls(read('self/uid_map'), owner, int(read('sys/kernel/overflowuid')))
        finally:
            os.close(root)

    def check(self, uid):
        if self.parent_uid(uid) != 0 and uid not in (0, self.owner):
            raise ValueError('ancestor owner unrelated')

    def parent_uid(self, uid):
        if uid != self.overflow or self.complete:
            for inside, outside, count in self.ranges:
                if inside <= uid < inside + count:
                    return outside + uid - inside
        raise ValueError('unmapped or ambiguous ancestor uid')
