package cachefile

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/stretchr/testify/require"
)

func newStorageTestCache(t *testing.T) *CacheFile {
	t.Helper()
	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	return &CacheFile{DB: database}
}

func TestStorageRoundTripAndDelete(t *testing.T) {
	t.Parallel()
	cache := newStorageTestCache(t)
	value := []byte(`{"enabled":true}`)
	require.NoError(t, cache.SaveStorage("settings", value))
	require.Equal(t, value, cache.LoadStorage("settings"))
	require.NoError(t, cache.DeleteStorage("settings"))
	require.Nil(t, cache.LoadStorage("settings"))
}

func TestStorageSeparatesCacheIDs(t *testing.T) {
	t.Parallel()
	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	first := &CacheFile{DB: database, cacheID: []byte{0, 'a'}}
	second := &CacheFile{DB: database, cacheID: []byte{0, 'b'}}
	require.NoError(t, first.SaveStorage("key", []byte(`"first"`)))
	require.NoError(t, second.SaveStorage("key", []byte(`"second"`)))
	require.Equal(t, []byte(`"first"`), first.LoadStorage("key"))
	require.Equal(t, []byte(`"second"`), second.LoadStorage("key"))
}

func TestStorageEvictsOldestEntry(t *testing.T) {
	t.Parallel()
	cache := newStorageTestCache(t)
	for i := 0; i < 2; i++ {
		require.NoError(t, cache.SaveStorage(string(rune('a'+i)), make([]byte, storageSizeLimit/2)))
	}
	require.NoError(t, cache.SaveStorage("new", []byte("value")))
	require.Nil(t, cache.LoadStorage("a"))
	require.NotNil(t, cache.LoadStorage("b"))
	require.Equal(t, []byte("value"), cache.LoadStorage("new"))
}
