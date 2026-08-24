package cachefile

import (
	"encoding/binary"
	"sort"
	"time"

	"github.com/sagernet/bbolt"
)

const (
	storageSizeLimit    = 1024 * 1024
	storageKeySizeLimit = 64
	maxStorageEntries   = storageSizeLimit / storageKeySizeLimit
	storageTimeSize     = 8
)

type storageEntry struct {
	key  string
	data []byte
	time int64
}

func (c *CacheFile) LoadStorage(key string) []byte {
	var data []byte
	if len([]byte(key)) > storageKeySizeLimit {
		return nil
	}
	_ = c.view(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, bucketStorage)
		if bucket == nil {
			return nil
		}
		value := bucket.Get([]byte(key))
		if len(value) < storageTimeSize {
			return nil
		}
		data = append([]byte(nil), value[storageTimeSize:]...)
		return nil
	})
	return data
}

func (c *CacheFile) SaveStorage(key string, data []byte) error {
	if len([]byte(key)) == 0 || len([]byte(key)) > storageKeySizeLimit {
		return nil
	}
	if len(data) > storageSizeLimit {
		return nil
	}
	now := time.Now().UnixNano()
	value := make([]byte, storageTimeSize+len(data))
	binary.BigEndian.PutUint64(value, uint64(now))
	copy(value[storageTimeSize:], data)
	return c.batch(func(tx *bbolt.Tx) error {
		bucket, err := c.createBucket(tx, bucketStorage)
		if err != nil {
			return err
		}
		entries := make([]storageEntry, 0)
		usedSize := 0
		cursor := bucket.Cursor()
		for entryKey, entryValue := cursor.First(); entryKey != nil; entryKey, entryValue = cursor.Next() {
			if len(entryValue) < storageTimeSize {
				if err = bucket.Delete(entryKey); err != nil {
					return err
				}
				continue
			}
			entry := storageEntry{key: string(entryKey), data: entryValue[storageTimeSize:], time: int64(binary.BigEndian.Uint64(entryValue))}
			if entry.key != key {
				entries = append(entries, entry)
				usedSize += len(entry.data)
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].time == entries[j].time {
				return entries[i].key < entries[j].key
			}
			return entries[i].time < entries[j].time
		})
		for usedSize+len(data) > storageSizeLimit || len(entries) >= maxStorageEntries {
			if len(entries) == 0 {
				break
			}
			if err = bucket.Delete([]byte(entries[0].key)); err != nil {
				return err
			}
			usedSize -= len(entries[0].data)
			entries = entries[1:]
		}
		return bucket.Put([]byte(key), value)
	})
}

func (c *CacheFile) DeleteStorage(key string) error {
	return c.batch(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, bucketStorage)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(key))
	})
}
