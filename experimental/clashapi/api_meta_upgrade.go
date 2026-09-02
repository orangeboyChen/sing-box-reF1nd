package clashapi

import (
	"net/http"
	"os/exec"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func upgradeRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Post("/", updateCore(server))
	r.Post("/ui", updateExternalUI(server))
	return r
}

func updateCore(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		channel := strings.ToLower(r.URL.Query().Get("channel"))
		if channel == "" {
			channel = "auto"
		}
		if channel != "auto" && channel != "release" && channel != "alpha" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("channel must be auto, release, or alpha"))
			return
		}
		if server.coreUpgradeScript == "" {
			render.Status(r, http.StatusNotImplemented)
			render.JSON(w, r, newError("core upgrade is not configured"))
			return
		}
		cmd := exec.Command(server.coreUpgradeScript, "update_core", channel)
		if err := cmd.Run(); err != nil {
			server.logger.Error(E.Cause(err, "start core upgrade"))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{"status": "ok"})
	}
}

func updateExternalUI(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if server.externalUI == "" {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("external UI not enabled"))
			return
		}
		server.logger.Info("upgrading external UI")
		err := server.checkAndDownloadExternalUI(true)
		if err != nil {
			server.logger.Error(E.Cause(err, "upgrade external UI"))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{"status": "ok"})
	}
}
