
import asyncio
import concurrent.futures
import os
import struct
from typing import Optional, Tuple

from arka.crypto import keccak_800


class AsyncFileProcessor:
    """
    Manages asynchronous file operations with multiple file handles for concurrent access.

    Thread Safety:
    - Reads (`read`, `get_size`) are thread-safe without locks, as each operation uses a unique file handle.
    - Writes (`write`, `append`, `truncate`) are atomic for non-overlapping offsets or end-of-file operations
      due to immediate flushes, but concurrent writes to overlapping offsets may cause corruption.
    - Use an external lock (e.g., `asyncio.Lock`) for:
      - Concurrent writes to the same offset or overlapping regions.
      - Sequences requiring write consistency (e.g., write then read).
    """

    def __init__(self, file_path: str, num_handles: int | None = None, loop: asyncio.AbstractEventLoop | None = None, executor: concurrent.futures.Executor | None = None):
        self.file_path = file_path
        self.num_handles = num_handles or self._get_default_executor_thread_count()
        self.loop = loop or asyncio.get_running_loop()
        self.executor = executor
        self.queue = asyncio.Queue(maxsize=self.num_handles)
        for _ in range(self.num_handles):
            f = open(file_path, 'r+b')
            self.queue.put_nowait(f)
    
    @staticmethod
    def _get_default_executor_thread_count() -> int:
        cpu_count = os.cpu_count() or 1
        return min(32, cpu_count + 4)
    
    def sync_read(self, handle: object, offset: int, size: int) -> bytes:
        handle.seek(offset)
        data = handle.read(size)
        return data
    
    def sync_write(self, handle: object, offset: int, data: bytes) -> int:
        handle.seek(offset)
        bytes_written = handle.write(data)
        handle.flush()
        return bytes_written
    
    def sync_truncate(self, handle: object, size: int) -> None:
        handle.truncate(size)
        handle.flush()
    
    def sync_get_size(self, handle: object) -> int:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        return size
    
    async def get_handle(self) -> object:
        return await self.queue.get()
    
    async def release_handle(self, handle: object) -> None:
        await self.queue.put(handle)
    
    def close(self) -> None:
        while not self.queue.empty():
            f = self.queue.get_nowait()
            f.close()
    
    async def read(self, offset: int, size: int) -> bytes:
        handle = await self.get_handle()
        try:
            return await self.loop.run_in_executor(self.executor, self.sync_read, handle, offset, size)
        finally:
            await self.release_handle(handle)
    
    async def write(self, offset: int, data: bytes) -> int:
        handle = await self.get_handle()
        try:
            return await self.loop.run_in_executor(self.executor, self.sync_write, handle, offset, data)
        finally:
            await self.release_handle(handle)
    
    async def truncate(self, size: int) -> None:
        handle = await self.get_handle()
        try:
            await self.loop.run_in_executor(self.executor, self.sync_truncate, handle, size)
        finally:
            await self.release_handle(handle)
    
    async def get_size(self) -> int:
        handle = await self.get_handle()
        try:
            return await self.loop.run_in_executor(self.executor, self.sync_get_size, handle)
        finally:
            await self.release_handle(handle)
    
    async def append(self, item: bytes) -> int:
        handle = await self.get_handle()
        try:
            handle.seek(0, os.SEEK_END)
            bytes_written = handle.write(item)
            handle.flush()
            return bytes_written
        finally:
            await self.release_handle(handle)


class AsyncPersistentDictionary:
    """
    A persistent dictionary storing bytes keys and values using a hash table on disk.

    File Structure:
    - keys_file: Hash table with ENTRY_SIZE-byte entries (22-byte hashed key, 8-byte value offset, 2-byte value length).
    - values_file: Header (16-byte salt, 8-byte item_count), followed by concatenated bytes values.

    Thread Safety:
    - Reads (`__contains__`, `__getitem__`, `get`, `__len__`) are thread-safe without locks, using isolated file handles
      and atomic cache reads. May see stale cache briefly but will refresh via `_load_state`.
    - Writes (`__setitem__`, `__delitem__`, `update`, `difference_update`) are atomic for individual file operations but
      require locks for:
      - Concurrent writes to prevent corruption of keys_file or values_file (e.g., overlapping hash table entries, item_count).
      - Read-after-write consistency (e.g., set then get requires write completion).
      - Atomic sequences (e.g., check if key exists then set).
    - Use an external `asyncio.Lock` for these scenarios. Example:
      ```python
      lock = asyncio.Lock()
      async with lock:
          await dict.__setitem__(b'key', b'value')
          value = await dict.__getitem__(b'key')
      ```

    Usage Notes:
    - Initialize with `await AsyncPersistentDictionary.create(keys_file, values_file)`.
    - Call `await close()` to free resources.
    - Table size is 2^n, where n = max(3, item_count.bit_length() + 2).
    - Keys are hashed with keccak_800(salt + key, 22) for 22-byte hashed keys.
    """

    HEADER_SIZE = 24  # 16 bytes salt + 8 bytes item_count
    ENTRY_SIZE = 32   # 22 bytes hashed key + 8 bytes offset + 2 bytes length
    EMPTY_ENTRY = b'\x00' * ENTRY_SIZE
    DELETED_ENTRY = b'\xff' * ENTRY_SIZE

    @classmethod
    async def create(cls, keys_file: str, values_file: str) -> 'AsyncPersistentDictionary':
        """Create and initialize an instance with specified file paths."""
        instance = cls(keys_file, values_file)
        await instance._initialize()
        return instance

    def __init__(self, keys_file: str, values_file: str):
        """
        Initialize with configurable file paths.
        
        :param keys_file: Path to the hash table file.
        :param values_file: Path to the values file.
        """
        self.keys_file = keys_file
        self.values_file = values_file
        self.keys_processor = AsyncFileProcessor(keys_file)
        self.values_processor = AsyncFileProcessor(values_file)
        # Cached properties
        self._table_size: Optional[int] = None
        self._n: Optional[int] = None
        self._key_mask: Optional[int] = None
        self._salt: Optional[bytes] = None
        self._item_count: Optional[int] = None

    def __await__(self):
        """Make the dictionary awaitable, returning the initialization coroutine."""
        return self._initialize().__await__()

    async def _initialize(self) -> None:
        """Initialize files if they don't exist. Called once at creation."""
        if not os.path.exists(self.values_file):
            salt = os.urandom(16)
            item_count = 0
            header = salt + struct.pack('<Q', item_count)
            await self.values_processor.write(0, header)
            self._salt = salt
            self._item_count = item_count
        
        if not os.path.exists(self.keys_file):
            initial_n = 3  # 2^3 = 8 slots
            initial_table_size = 2 ** initial_n
            empty_entries = self.EMPTY_ENTRY * initial_table_size
            await self.keys_processor.write(0, empty_entries)
            self._table_size = initial_table_size
            self._n = initial_n
            self._key_mask = (1 << initial_n) - 1
        
        if any(x is None for x in (self._salt, self._item_count, self._table_size, self._n, self._key_mask)):
            await self._load_state()

    async def _load_state(self) -> None:
        """Load salt, item_count, table_size, n, and key_mask from files."""
        # Load header from values_file
        header = await self.values_processor.read(0, self.HEADER_SIZE)
        if len(header) != self.HEADER_SIZE:
            raise IOError("Invalid header in values_file")
        self._salt = header[:16]
        self._item_count = struct.unpack('<Q', header[16:])[0]
        
        # Load table_size from keys_file
        keys_size = await self.keys_processor.get_size()
        self._table_size = max(2, keys_size // self.ENTRY_SIZE)
        
        # Compute n and key_mask
        self._n = max(3, self._item_count.bit_length() + 2)
        self._key_mask = (1 << self._n) - 1

    async def _get_salt(self) -> bytes:
        """Get cached salt, loading it if necessary."""
        if self._salt is None:
            await self._load_state()
        return self._salt

    async def _get_item_count(self) -> int:
        """Get cached item_count, loading it if necessary."""
        if self._item_count is None:
            await self._load_state()
        return self._item_count

    async def _set_item_count(self, count: int) -> None:
        """Write item_count to values_file and update cache."""
        await self.values_processor.write(16, struct.pack('<Q', count))
        self._item_count = count

    async def _get_table_size(self) -> int:
        """Get cached table_size, computing it if necessary."""
        if self._table_size is None:
            await self._load_state()
        return self._table_size

    async def _get_n(self) -> int:
        """Get cached n, computing it based on item_count."""
        if self._n is None:
            await self._load_state()
        return self._n

    async def _get_key_mask(self) -> int:
        """Get cached key_mask, computing it if necessary."""
        if self._key_mask is None:
            await self._load_state()
        return self._key_mask

    async def _hash_key(self, key: bytes) -> bytes:
        """Compute the 22-byte hash of salt + key."""
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object")
        salt = await self._get_salt()
        return await keccak_800(salt + key, 22)

    async def _get_index(self, hashed_key: bytes) -> int:
        """Get the slot index from the first n bits of the hashed key."""
        n = await self._get_n()
        key_mask = await self._get_key_mask()
        bits_needed = (n + 7) // 8
        index = int.from_bytes(hashed_key[:bits_needed], 'little') & key_mask
        return index

    async def _resize_table(self, new_n: int) -> None:
        """
        Resize the hash table to 2^new_n slots.
        Requires a lock to prevent concurrent writes or resizes.
        """
        new_table_size = 1 << new_n
        new_size_bytes = new_table_size * self.ENTRY_SIZE
        keys_size = await self.keys_processor.get_size()
        num_entries = keys_size // self.ENTRY_SIZE
        entries = []
        
        # Read existing entries
        for i in range(num_entries):
            entry_data = await self.keys_processor.read(i * self.ENTRY_SIZE, self.ENTRY_SIZE)
            if entry_data != self.EMPTY_ENTRY and entry_data != self.DELETED_ENTRY:
                entries.append(entry_data)
        
        # Write new empty table
        await self.keys_processor.truncate(0)
        await self.keys_processor.write(0, self.EMPTY_ENTRY * new_table_size)
        
        # Reinsert entries
        new_key_mask = (1 << new_n) - 1
        for entry_data in entries:
            hashed_key = entry_data[:22]
            bits_needed = (new_n + 7) // 8
            index = int.from_bytes(hashed_key[:bits_needed], 'little') & new_key_mask
            while True:
                probe_data = await self.keys_processor.read(index * self.ENTRY_SIZE, self.ENTRY_SIZE)
                if probe_data == self.EMPTY_ENTRY or probe_data == self.DELETED_ENTRY:
                    await self.keys_processor.write(index * self.ENTRY_SIZE, entry_data)
                    break
                index = (index + 1) % new_table_size
        
        # Update caches
        self._table_size = new_table_size
        self._n = new_n
        self._key_mask = new_key_mask

    async def _find_entry(self, key: bytes) -> Optional[Tuple[int, int, int]]:
        """
        Find the entry for a key in keys_file.
        Returns (index, offset, length) or None if not found. Thread-safe without locks.
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object")
        hashed_key = await self._hash_key(key)
        table_size = await self._get_table_size()
        index = await self._get_index(hashed_key)
        
        for _ in range(table_size):
            entry_data = await self.keys_processor.read(index * self.ENTRY_SIZE, self.ENTRY_SIZE)
            if len(entry_data) != self.ENTRY_SIZE or entry_data == self.EMPTY_ENTRY:
                return None
            if entry_data != self.DELETED_ENTRY:
                entry_key = entry_data[:22]
                if entry_key == hashed_key:
                    offset = struct.unpack('<Q', entry_data[22:30])[0]
                    length = struct.unpack('<H', entry_data[30:])[0]
                    return index, offset, length
            index = (index + 1) % table_size
        return None

    async def __contains__(self, key: bytes) -> bool:
        """Check if a key exists. Thread-safe without locks."""
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object")
        entry = await self._find_entry(key)
        return entry is not None

    async def __getitem__(self, key: bytes) -> bytes:
        """Get a value by key. Thread-safe without locks."""
        entry = await self._find_entry(key)
        if entry is None:
            raise KeyError("Key not found")
        _, offset, length = entry
        value = await self.values_processor.read(offset, length)
        return value

    async def get(self, item: bytes, default: Optional[bytes] = None) -> Optional[bytes]:
        """Get a value by key, returning default if not found. Thread-safe without locks."""
        if not isinstance(item, bytes):
            raise ValueError("Item must be a bytes object")
        entry = await self._find_entry(item)
        if entry is None:
            return default
        _, offset, length = entry
        value = await self.values_processor.read(offset, length)
        return value

    async def __setitem__(self, key: bytes, value: bytes) -> None:
        """
        Set a key-value pair.
        Atomic for individual sets but requires a lock for concurrent sets or mixed writes.
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be a bytes object")
        if not isinstance(value, bytes):
            raise ValueError("Value must be a bytes object")
        
        item_count = await self._get_item_count()
        n = await self._get_n()
        new_n = max(3, (item_count + 1).bit_length() + 2)
        
        if new_n > n:
            await self._resize_table(new_n)
        
        entry = await self._find_entry(key)
        values_size = await self.values_processor.get_size()
        value_offset = values_size
        await self.values_processor.append(value)
        
        hashed_key = await self._hash_key(key)
        entry_data = hashed_key + struct.pack('<Q', value_offset) + struct.pack('<H', len(value))
        
        if entry is None:
            table_size = await self._get_table_size()
            index = await self._get_index(hashed_key)
            for _ in range(table_size):
                probe_data = await self.keys_processor.read(index * self.ENTRY_SIZE, self.ENTRY_SIZE)
                if probe_data == self.EMPTY_ENTRY or probe_data == self.DELETED_ENTRY:
                    await self.keys_processor.write(index * self.ENTRY_SIZE, entry_data)
                    await self._set_item_count(item_count + 1)
                    break
                index = (index + 1) % table_size
            else:
                raise RuntimeError("Hash table full")
        else:
            index, _, _ = entry
            await self.keys_processor.write(index * self.ENTRY_SIZE, entry_data)

    async def __delitem__(self, key: bytes) -> None:
        """
        Delete a key-value pair.
        Atomic for individual deletions but requires a lock for concurrent deletions or mixed writes.
        """
        entry = await self._find_entry(key)
        if entry is None:
            raise KeyError("Key not found")
        
        index, _, _ = entry
        item_count = await self._get_item_count()
        await self.keys_processor.write(index * self.ENTRY_SIZE, self.DELETED_ENTRY)
        await self._set_item_count(item_count - 1)
        
        n = await self._get_n()
        new_n = max(3, (item_count - 1).bit_length() + 2)
        if new_n < n:
            await self._resize_table(new_n)

    async def update(self, items: dict[bytes, bytes]) -> None:
        """
        Update the dictionary with key-value pairs.
        Requires a lock for concurrent updates or mixed writes to ensure consistency.
        """
        if not isinstance(items, dict):
            raise TypeError("Items must be a dictionary")
        for key, value in items.items():
            if not isinstance(key, bytes) or not isinstance(value, bytes):
                raise ValueError("Keys and values must be bytes objects")
        
        item_count = await self._get_item_count()
        n = await self._get_n()
        new_n = max(3, (item_count + len(items)).bit_length() + 2)
        if new_n > n:
            await self._resize_table(new_n)
        
        for key, value in items.items():
            await self.__setitem__(key, value)

    async def difference_update(self, keys: list[bytes]) -> None:
        """
        Remove keys from the dictionary that exist in keys.
        Requires a lock for concurrent updates or mixed writes to ensure consistency.
        """
        if not isinstance(keys, set):
            raise TypeError("Items must be a set")
        for key in keys:
            if not isinstance(key, bytes):
                raise ValueError("Keys must be bytes objects")
        
        item_count = await self._get_item_count()
        n = await self._get_n()
        deleted_count = 0
        
        for key in keys:
            try:
                await self.__delitem__(key)
                deleted_count += 1
            except KeyError:
                pass
        
        new_n = max(3, (item_count - deleted_count).bit_length() + 2)
        if new_n < n:
            await self._resize_table(new_n)

    async def __len__(self) -> int:
        """Return the number of key-value pairs. Thread-safe without locks."""
        return await self._get_item_count()

    async def close(self) -> None:
        """Close all file handles."""
        self.keys_processor.close()
        self.values_processor.close()


class AsyncPersistentLog:
    """
    A persistent log storing bytes values with offsets, supporting append and slicing.

    File Structure:
    - offsets_file: 8-byte start_index header, followed by n+1 8-byte pointers.
      - start_index: Number of skipped values.
      - n pointers: Offsets to values in values_file.
      - Last pointer: Total size of values_file.
    - values_file: Concatenated bytes values.

    Thread Safety:
    - Reads (`__getitem__`, `__len__`) are thread-safe without locks, using isolated file handles
      and atomic cache reads. May see stale cache briefly but will refresh via `_load_state`.
    - Writes (`append`, `truncate`, `compact`) are atomic for individual file operations but
      require locks for:
      - Concurrent writes (e.g., multiple `append`, `truncate`, or `compact`) to prevent
        corruption of offsets or values files.
      - Read-after-write consistency (e.g., append then read requires write completion).
      - Atomic sequences (e.g., check length then append if below threshold).
    - Use an external `asyncio.Lock` for these scenarios. Example:
      ```python
      lock = asyncio.Lock()
      async with lock:
          await log.append(b'value')
          value = await log[await log.__len__() - 1]
      ```

    Usage Notes:
    - Initialize with `await AsyncPersistentLog.create(offsets_file, values_file)`.
    - Call `await close()` to free resources.
    - Use `compact` periodically to reclaim space from skipped values.
    """

    HEADER_SIZE = 8  # 8-byte start_index
    OFFSET_SIZE = 8  # 8-byte pointers

    @classmethod
    async def create(cls, offsets_file: str, values_file: str) -> 'AsyncPersistentLog':
        """Create and initialize an instance with specified file paths."""
        instance = cls(offsets_file, values_file)
        await instance._initialize()
        return instance

    def __init__(self, offsets_file: str, values_file: str):
        """
        Initialize with configurable file paths.
        
        :param offsets_file: Path to offsets file (header + n+1 pointers)
        :param values_file: Path to values file (concatenated bytes)
        """
        self.offsets_file = offsets_file
        self.values_file = values_file
        self.offsets_processor = AsyncFileProcessor(offsets_file)
        self.values_processor = AsyncFileProcessor(values_file)
        # Cached properties
        self._start_index: Optional[int] = None
        self._item_count: Optional[int] = None
        self._values_size: Optional[int] = None

    async def _initialize(self) -> None:
        """Initialize files if they don't exist. Called once at creation."""
        if not os.path.exists(self.values_file):
            await self.values_processor.write(0, b'')
            self._values_size = 0
        if not os.path.exists(self.offsets_file):
            # Initialize with header (start_index = 0) and one offset (values_size = 0)
            await self.offsets_processor.write(0, struct.pack('<Q', 0))  # start_index
            await self.offsets_processor.write(self.HEADER_SIZE, struct.pack('<Q', 0))  # values_size
            self._start_index = 0
            self._item_count = 0
        if any(x is None for x in (self._start_index, self._item_count, self._values_size)):
            await self._load_state()

    async def _load_state(self) -> None:
        """Load start_index, item_count, and values_size from offsets file."""
        offsets_size = await self.offsets_processor.get_size()
        if offsets_size < self.HEADER_SIZE + self.OFFSET_SIZE:
            raise IOError("Offsets file too small")
        if (offsets_size - self.HEADER_SIZE) % self.OFFSET_SIZE != 0:
            raise IOError("Invalid offsets file size")
        
        # Read start_index
        start_index_data = await self.offsets_processor.read(0, self.HEADER_SIZE)
        self._start_index = struct.unpack('<Q', start_index_data)[0]
        
        # Calculate item_count
        self._item_count = (offsets_size - self.HEADER_SIZE) // self.OFFSET_SIZE - 1
        
        # Read values_size (last offset)
        values_size_data = await self.offsets_processor.read(offsets_size - self.OFFSET_SIZE, self.OFFSET_SIZE)
        self._values_size = struct.unpack('<Q', values_size_data)[0]

    async def _get_start_index(self) -> int:
        """Get cached start_index, loading it if necessary."""
        if self._start_index is None:
            await self._load_state()
        return self._start_index

    async def _get_item_count(self) -> int:
        """Get cached item_count, loading it if necessary."""
        if self._item_count is None:
            await self._load_state()
        return self._item_count

    async def _get_values_size(self) -> int:
        """Get cached values_size, loading it if necessary."""
        if self._values_size is None:
            await self._load_state()
        return self._values_size

    async def append(self, value: bytes) -> None:
        """
        Append a bytes value to the end of the log.
        Atomic for individual appends but requires a lock for concurrent appends
        or mixed write operations to ensure offset consistency.
        """
        if not isinstance(value, bytes):
            raise ValueError("Value must be a bytes object")
        
        item_count = await self._get_item_count()
        values_size = await self._get_values_size()
        
        # Append value to values file
        bytes_written = await self.values_processor.append(value)
        if bytes_written != len(value):
            raise IOError("Incomplete append to values file")
        
        # Append new offset (current values_size)
        offset_pos = self.HEADER_SIZE + item_count * self.OFFSET_SIZE
        await self.offsets_processor.write(offset_pos, struct.pack('<Q', values_size))
        
        # Update last offset (new values_size)
        new_values_size = values_size + len(value)
        await self.offsets_processor.write(offset_pos + self.OFFSET_SIZE, struct.pack('<Q', new_values_size))
        
        # Update caches
        self._item_count = item_count + 1
        self._values_size = new_values_size

    async def __getitem__(self, index: int) -> bytes:
        """Get the value at index (relative to start_index). Thread-safe without locks."""
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        
        item_count = await self._get_item_count()
        if index < 0:
            index += item_count
        if index < 0 or index >= item_count:
            raise IndexError("Index out of range")
        
        start_index = await self._get_start_index()
        abs_index = start_index + index
        
        # Read offsets
        offset_pos = self.HEADER_SIZE + abs_index * self.OFFSET_SIZE
        offset_data = await self.offsets_processor.read(offset_pos, self.OFFSET_SIZE)
        next_offset_data = await self.offsets_processor.read(offset_pos + self.OFFSET_SIZE, self.OFFSET_SIZE)
        offset = struct.unpack('<Q', offset_data)[0]
        next_offset = struct.unpack('<Q', next_offset_data)[0]
        
        # Read value
        value_length = next_offset - offset
        value = await self.values_processor.read(offset, value_length)
        return value

    async def truncate(self, start: Optional[int] = None, end: Optional[int] = None) -> None:
        """
        Truncate the log to keep values from start to end (in-place slice).
        Atomic for individual truncates but requires a lock for concurrent truncates
        or mixed write operations to prevent file corruption.
        """
        if not all(isinstance(x, (int, type(None))) for x in (start, end)):
            raise TypeError("Start and end must be integers or None")
        
        item_count = await self._get_item_count()
        start_index = await self._get_start_index()
        
        # Normalize start and end
        start = 0 if start is None else start
        end = item_count if end is None else end
        if start < 0:
            start += item_count
        if end < 0:
            end += item_count
        if start < 0 or end < 0 or start > end or end > item_count:
            raise ValueError("Invalid start or end indices")
        
        if start == 0 and end == item_count:
            return
        
        # Update start_index for start truncation
        new_start_index = start_index + start
        
        # Get new values_size for end truncation
        if end == item_count:
            new_values_size = await self._get_values_size()
        else:
            end_offset_pos = self.HEADER_SIZE + (start_index + end) * self.OFFSET_SIZE
            new_values_size_data = await self.offsets_processor.read(end_offset_pos, self.OFFSET_SIZE)
            new_values_size = struct.unpack('<Q', new_values_size_data)[0]
        
        # Write new start_index
        await self.offsets_processor.write(0, struct.pack('<Q', new_start_index))
        
        # Shift offsets to start at index 0
        if start > 0:
            offsets_data = await self.offsets_processor.read(self.HEADER_SIZE + start * self.OFFSET_SIZE, (end - start + 1) * self.OFFSET_SIZE)
            await self.offsets_processor.write(self.HEADER_SIZE, offsets_data)
        
        # Truncate offsets file
        new_offsets_size = self.HEADER_SIZE + (end - start + 1) * self.OFFSET_SIZE
        await self.offsets_processor.truncate(new_offsets_size)
        
        # Truncate values file
        await self.values_processor.truncate(new_values_size)
        
        # Update caches
        self._start_index = new_start_index
        self._item_count = end - start
        self._values_size = new_values_size

    async def compact(self, new_offsets_file: str, new_values_file: str) -> None:
        """
        Copy active values and offsets to new files, resetting start_index.
        Requires a lock to prevent concurrent writes to the original files during compaction.
        """
        item_count = await self._get_item_count()
        if item_count == 0:
            # Create empty files
            new_offsets_processor = AsyncFileProcessor(new_offsets_file)
            new_values_processor = AsyncFileProcessor(new_values_file)
            await new_offsets_processor.write(0, struct.pack('<Q', 0))  # start_index
            await new_offsets_processor.write(self.HEADER_SIZE, struct.pack('<Q', 0))  # values_size
            await new_values_processor.write(0, b'')
            new_offsets_processor.close()
            new_values_processor.close()
            return
        
        # Create new processors
        new_offsets_processor = AsyncFileProcessor(new_offsets_file)
        new_values_processor = AsyncFileProcessor(new_values_file)
        
        # Write new start_index (0)
        await new_offsets_processor.write(0, struct.pack('<Q', 0))
        
        new_values_offset = 0
        start_index = await self._get_start_index()
        
        # Copy active values and offsets
        for i in range(item_count):
            abs_index = start_index + i
            offset_pos = self.HEADER_SIZE + abs_index * self.OFFSET_SIZE
            offset_data = await self.offsets_processor.read(offset_pos, self.OFFSET_SIZE)
            next_offset_data = await self.offsets_processor.read(offset_pos + self.OFFSET_SIZE, self.OFFSET_SIZE)
            offset = struct.unpack('<Q', offset_data)[0]
            next_offset = struct.unpack('<Q', next_offset_data)[0]
            value_length = next_offset - offset
            
            # Read and append value
            value = await self.values_processor.read(offset, value_length)
            await new_values_processor.append(value)
            
            # Write new offset
            await new_offsets_processor.write(self.HEADER_SIZE + i * self.OFFSET_SIZE, struct.pack('<Q', new_values_offset))
            new_values_offset += value_length
        
        # Write new values_size
        await new_offsets_processor.write(self.HEADER_SIZE + item_count * self.OFFSET_SIZE, struct.pack('<Q', new_values_offset))
        
        # Close new processors
        new_offsets_processor.close()
        new_values_processor.close()
        
        # Update caches
        self._start_index = 0
        self._values_size = new_values_offset
        # item_count unchanged

    async def __len__(self) -> int:
        """Return the number of active values in the log. Thread-safe without locks."""
        return await self._get_item_count()

    async def close(self) -> None:
        """Close all file handles."""
        self.offsets_processor.close()
        self.values_processor.close()
