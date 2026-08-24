package clashapi

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const storageSizeLimit = 1024 * 1024
const storageKeySizeLimit = 64

func storageRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage(ctx))
	r.Put("/{key}", setStorage(ctx))
	r.Delete("/{key}", deleteStorage(ctx))
	return r
}

func getStorage(ctx context.Context) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var data []byte
		if cacheFile != nil {
			data = cacheFile.LoadStorage(getEscapeParam(r, "key"))
		}
		w.Header().Set("Content-Type", "application/json")
		if len(data) == 0 {
			_, _ = w.Write([]byte("null"))
			return
		}
		_, _ = w.Write(data)
	}
}

func setStorage(ctx context.Context) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, storageSizeLimit+1))
		if err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				render.Status(r, http.StatusRequestEntityTooLarge)
			} else {
				render.Status(r, http.StatusBadRequest)
			}
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if !stdjson.Valid(data) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		key := getEscapeParam(r, "key")
		if len([]byte(key)) == 0 || len([]byte(key)) > storageKeySizeLimit {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid storage key"))
			return
		}
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile != nil {
			if err = cacheFile.SaveStorage(key, data); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(err.Error()))
				return
			}
		}
		render.NoContent(w, r)
	}
}

func deleteStorage(ctx context.Context) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile != nil {
			if err := cacheFile.DeleteStorage(getEscapeParam(r, "key")); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(err.Error()))
				return
			}
		}
		render.NoContent(w, r)
	}
}
