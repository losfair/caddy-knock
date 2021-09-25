package knock

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Knock{})
	httpcaddyfile.RegisterHandlerDirective("knock", parseCaddyfile)
}

// Gizmo is an example; put your own type here.
type Knock struct {
	logger          *zap.Logger
	permissionCache *ttlcache.Cache
	httpClient      http.Client
	Server          string `json:"server"`
	Svcname         string `json:"svcname"`
	Svcsecret       string `json:"svcsecret"`
}

// CaddyModule returns the Caddy module information.
func (Knock) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.knock",
		New: func() caddy.Module { return new(Knock) },
	}
}

func (k *Knock) loadPermission(key string) (data interface{}, ttl time.Duration, err error) {
	type SvcQuery struct {
		Svcname   string `json:"svcname"`
		Svcsecret string `json:"svcsecret"`
		Userip    string `json:"userip"`
	}
	q := &SvcQuery{
		Svcname:   k.Svcname,
		Svcsecret: k.Svcsecret,
		Userip:    key,
	}
	binQ, err := json.Marshal(&q)
	if err != nil {
		return nil, 0, err
	}
	res, err := k.httpClient.Post(k.Server+"/query", "application/json", bytes.NewReader(binQ))
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	resData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	if res.StatusCode != 200 {
		return nil, 0, errors.New(string(resData))
	}

	type SvcRes struct {
		Ok bool `json:"ok"`
	}
	var svcRes SvcRes
	if err := json.Unmarshal(resData, &svcRes); err != nil {
		return nil, 0, err
	}
	ok := svcRes.Ok

	if ok {
		k.logger.Info("granted access", zap.String("ip", key))
		return true, 1 * time.Hour, nil
	} else {
		return false, 10 * time.Second, nil
	}
}

func (k *Knock) Cleanup() error {
	k.permissionCache.Close()
	return nil
}

func (k *Knock) Provision(ctx caddy.Context) error {
	k.logger = ctx.Logger(k)
	k.permissionCache = ttlcache.NewCache()
	k.permissionCache.SetLoaderFunction(k.loadPermission)
	return nil
}

// Validate implements caddy.Validator.
func (k *Knock) Validate() error {
	if k.Server == "" {
		return errors.New("missing `server`")
	}
	if k.Svcname == "" {
		return errors.New("missing `svcname`")
	}
	if k.Svcsecret == "" {
		return errors.New("missing `svcsecret`")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (k *Knock) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}
	perm, err := k.permissionCache.Get(host)
	if err != nil {
		return err
	}

	if !perm.(bool) {
		w.Header().Add("location", k.Server+"/")
		w.WriteHeader(302)
		w.Write([]byte("knock required"))
		return nil
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (k *Knock) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "server":
				if !d.Args(&k.Server) {
					return d.ArgErr()
				}
			case "svcname":
				if !d.Args(&k.Svcname) {
					return d.ArgErr()
				}
			case "svcsecret":
				if !d.Args(&k.Svcsecret) {
					return d.ArgErr()
				}
			default:
				return d.ArgErr()
			}
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var k Knock
	err := k.UnmarshalCaddyfile(h.Dispenser)
	return &k, err
}

var (
	_ caddy.Provisioner           = (*Knock)(nil)
	_ caddy.Validator             = (*Knock)(nil)
	_ caddyhttp.MiddlewareHandler = (*Knock)(nil)
	_ caddyfile.Unmarshaler       = (*Knock)(nil)
	_ caddy.CleanerUpper          = (*Knock)(nil)
)
