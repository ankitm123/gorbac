package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	gorbac "github.com/mikespook/gorbac/v3"
	"github.com/mikespook/possum"
	_ "modernc.org/sqlite"
)

//go:embed static
var staticFS embed.FS

// A permission is always "resource::action" — layer type, sep "::".
// We store only the composed ID; type/sep are implicit.
type roleState struct {
	parents     []string
	permissions map[string]struct{} // key = "resource::action"
}

type store struct {
	mu    sync.RWMutex
	db    *sql.DB
	roles map[string]*roleState
	rbac  *gorbac.RBAC[string]
}

var state *store

// ---- DB ----

const schema = `
CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS role_parents (
    role_id TEXT NOT NULL, parent_id TEXT NOT NULL,
    PRIMARY KEY (role_id, parent_id)
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL, perm_id TEXT NOT NULL,
    PRIMARY KEY (role_id, perm_id)
);`

func openDB(path string) (*sql.DB, bool, error) {
	firstCreate := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		firstCreate = true
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, false, err
	}
	if _, err = db.Exec(schema); err != nil {
		return nil, false, err
	}
	return db, firstCreate, nil
}

func loadFromDB(db *sql.DB) (*store, error) {
	s := &store{
		db:    db,
		roles: make(map[string]*roleState),
		rbac:  gorbac.New[string](),
	}

	rows, err := db.Query(`SELECT id FROM roles`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		s.roles[id] = &roleState{permissions: make(map[string]struct{})}
	}
	rows.Close()

	rows, err = db.Query(`SELECT role_id, parent_id FROM role_parents`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rid, pid string
		if err = rows.Scan(&rid, &pid); err != nil {
			rows.Close()
			return nil, err
		}
		if rs, ok := s.roles[rid]; ok {
			rs.parents = append(rs.parents, pid)
		}
	}
	rows.Close()

	rows, err = db.Query(`SELECT role_id, perm_id FROM role_permissions`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rid, pid string
		if err = rows.Scan(&rid, &pid); err != nil {
			rows.Close()
			return nil, err
		}
		if rs, ok := s.roles[rid]; ok {
			rs.permissions[pid] = struct{}{}
		}
	}
	rows.Close()

	s.rebuildRBAC()
	return s, nil
}

// rebuildRBAC must be called with mu.Lock held (or single-threaded init).
func (s *store) rebuildRBAC() {
	r := gorbac.New[string]()
	for id, rs := range s.roles {
		role := gorbac.NewRole[string](id)
		for permID := range rs.permissions {
			role.Assign(gorbac.NewLayerPermission(permID, "::"))
		}
		r.Add(role)
	}
	for id, rs := range s.roles {
		if len(rs.parents) > 0 {
			r.SetParents(id, rs.parents)
		}
	}
	s.rbac = r
}

// ---- Assertions ----

func buildAssertion(mode string, params map[string]string) gorbac.AssertionFunc[string] {
	switch mode {
	case "isWeekday":
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			d := time.Now().Weekday()
			return d != time.Saturday && d != time.Sunday
		}
	case "isWeekend":
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			d := time.Now().Weekday()
			return d == time.Saturday || d == time.Sunday
		}
	case "isOwner":
		owner, user := params["owner"], params["requestUser"]
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return owner == user
		}
	case "isNotOwner":
		owner, user := params["owner"], params["requestUser"]
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return owner != user
		}
	case "isLinux":
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return runtime.GOOS == "linux"
		}
	case "isWindows":
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return runtime.GOOS == "windows"
		}
	case "isHuman":
		userType := params["userType"]
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return userType == "human"
		}
	case "isAI":
		userType := params["userType"]
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			return userType == "ai"
		}
	case "is200", "is401", "is403", "is404", "is500":
		want := map[string]int{"is200": 200, "is401": 401, "is403": 403, "is404": 404, "is500": 500}[mode]
		url := params["url"]
		return func(_ *gorbac.RBAC[string], _ string, _ gorbac.Permission[string]) bool {
			resp, err := http.Get(url) //nolint:gosec
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == want
		}
	default:
		return nil
	}
}

// ---- Wire types ----

type RoleView struct {
	ID          string   `json:"id"`
	Parents     []string `json:"parents"`
	Permissions []string `json:"permissions"` // "resource::action" strings
}

type StateResponse struct {
	Roles []RoleView `json:"roles"`
}

// ---- Handlers ----

func handleState(w http.ResponseWriter, r *http.Request) {
	var views []RoleView
	gorbac.Walk(state.rbac, func(role gorbac.Role[string], parents []string) error {
		rv := RoleView{ID: role.ID, Parents: parents, Permissions: []string{}}
		if rv.Parents == nil {
			rv.Parents = []string{}
		}
		for _, p := range role.Permissions() {
			rv.Permissions = append(rv.Permissions, p.ID())
		}
		views = append(views, rv)
		return nil
	})
	if views == nil {
		views = []RoleView{}
	}
	resp := possum.NewResponse(r)
	resp.SetData(StateResponse{Roles: views})
	resp.Write(w)
}

func handleRoles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string   `json:"id"`
		Parents []string `json:"parents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if _, exists := state.roles[req.ID]; exists {
		http.Error(w, "role already exists", http.StatusConflict)
		return
	}
	for _, p := range req.Parents {
		if _, ok := state.roles[p]; !ok {
			http.Error(w, "parent role not found: "+p, http.StatusNotFound)
			return
		}
	}

	tx, err := state.db.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if _, err = tx.Exec(`INSERT INTO roles(id) VALUES(?)`, req.ID); err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	for _, p := range req.Parents {
		if _, err = tx.Exec(`INSERT INTO role_parents(role_id,parent_id) VALUES(?,?)`, req.ID, p); err != nil {
			tx.Rollback()
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if req.Parents == nil {
		req.Parents = []string{}
	}
	state.roles[req.ID] = &roleState{parents: req.Parents, permissions: make(map[string]struct{})}
	state.rebuildRBAC()

	resp := possum.NewResponse(r)
	resp.SetData(map[string]string{"id": req.ID})
	resp.Write(w)
}

func handleRoleByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	parts := strings.SplitN(path, "/", 3)
	roleID := parts[0]
	if roleID == "" {
		http.Error(w, "missing role id", http.StatusBadRequest)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		deleteRole(w, r, roleID)
		return
	}
	if len(parts) >= 2 && parts[1] == "permissions" {
		if r.Method == http.MethodPost {
			assignPermission(w, r, roleID)
			return
		}
		if r.Method == http.MethodDelete && len(parts) == 3 {
			revokePermission(w, r, roleID, parts[2])
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func deleteRole(w http.ResponseWriter, r *http.Request, roleID string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if _, ok := state.roles[roleID]; !ok {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	tx, err := state.db.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	for _, stmt := range []string{
		`DELETE FROM roles WHERE id=?`,
		`DELETE FROM role_parents WHERE role_id=? OR parent_id=?`,
		`DELETE FROM role_permissions WHERE role_id=?`,
	} {
		var execErr error
		if strings.Contains(stmt, "parent_id") {
			_, execErr = tx.Exec(stmt, roleID, roleID)
		} else {
			_, execErr = tx.Exec(stmt, roleID)
		}
		if execErr != nil {
			tx.Rollback()
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	delete(state.roles, roleID)
	for _, rs := range state.roles {
		filtered := rs.parents[:0]
		for _, p := range rs.parents {
			if p != roleID {
				filtered = append(filtered, p)
			}
		}
		rs.parents = filtered
	}
	state.rebuildRBAC()
	w.WriteHeader(http.StatusNoContent)
}

func assignPermission(w http.ResponseWriter, r *http.Request, roleID string) {
	var req struct {
		Permission string `json:"permission"` // "resource::action"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Permission == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	rs, ok := state.roles[roleID]
	if !ok {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	tx, err := state.db.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if _, err = tx.Exec(`INSERT OR REPLACE INTO role_permissions(role_id,perm_id) VALUES(?,?)`, roleID, req.Permission); err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	rs.permissions[req.Permission] = struct{}{}
	state.rebuildRBAC()

	resp := possum.NewResponse(r)
	resp.SetData(map[string]string{"permission": req.Permission})
	resp.Write(w)
}

func revokePermission(w http.ResponseWriter, r *http.Request, roleID, permID string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	rs, ok := state.roles[roleID]
	if !ok {
		http.Error(w, "role not found", http.StatusNotFound)
		return
	}
	if _, ok = rs.permissions[permID]; !ok {
		http.Error(w, "permission not assigned", http.StatusNotFound)
		return
	}
	if _, err := state.db.Exec(`DELETE FROM role_permissions WHERE role_id=? AND perm_id=?`, roleID, permID); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	delete(rs.permissions, permID)
	state.rebuildRBAC()
	w.WriteHeader(http.StatusNoContent)
}

type verifyReq struct {
	Role         string            `json:"role"`
	Resource     string            `json:"resource"` // combined with action → "resource::action"
	Action       string            `json:"action"`
	CheckMode    string            `json:"checkMode"`   // "single" | "any" | "all"
	AssertMode   string            `json:"assertMode"`
	AssertParams map[string]string `json:"assertParams"`
	Roles        []string          `json:"roles"` // extra roles for any/all
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Action == "" && req.Resource == "" {
		http.Error(w, "resource or action required", http.StatusBadRequest)
		return
	}
	if req.CheckMode == "" {
		req.CheckMode = "single"
	}

	permID := req.Resource + "::" + req.Action
	perm := gorbac.NewLayerPermission(permID, "::")
	assert := buildAssertion(req.AssertMode, req.AssertParams)

	state.mu.RLock()
	rbac := state.rbac
	state.mu.RUnlock()

	var granted bool
	switch req.CheckMode {
	case "any":
		roles := append([]string{req.Role}, req.Roles...)
		granted = gorbac.AnyGranted(rbac, roles, perm, assert)
	case "all":
		roles := append([]string{req.Role}, req.Roles...)
		granted = gorbac.AllGranted(rbac, roles, perm, assert)
	default:
		granted = rbac.IsGranted(req.Role, perm, assert)
	}

	resp := possum.NewResponse(r)
	resp.SetData(map[string]interface{}{
		"granted":    granted,
		"permission": permID,
	})
	resp.Write(w)
}

// ---- Seed ----

var seedData = struct {
	roles []struct {
		id      string
		parents []string
	}
	assigns []struct{ role, perm string }
}{
	roles: []struct {
		id      string
		parents []string
	}{
		{"human", nil},
		{"ai", nil},
		{"guest", []string{"human"}},
		{"member", []string{"guest"}},
		{"editor", []string{"member"}},
		{"admin", []string{"editor"}},
		{"superadmin", []string{"admin"}},
	},
	assigns: []struct{ role, perm string }{
		{"ai", "article::read"},
		{"ai", "comment::read"},
		{"ai", "comment::react"},
		{"ai", "profile::read"},
		{"ai", "image::read"},
		{"ai", "video::read"},
		{"ai", "video::react"},
		{"guest", "article::read"},
		{"guest", "comment::read"},
		{"guest", "profile::read"},
		{"guest", "image::read"},
		{"guest", "video::read"},
		{"member", "comment::edit"},
		{"member", "profile::edit"},
		{"editor", "article::edit"},
		{"editor", "article::delete"},
		{"editor", "image::edit"},
		{"editor", "image::delete"},
		{"editor", "video::edit"},
		{"editor", "video::delete"},
		{"editor", "tag::edit"},
		{"editor", "category::edit"},
		{"admin", "report::edit"},
		{"admin", "setting::edit"},
		{"admin", "comment::delete"},
		{"superadmin", "audit-log::read"},
		{"superadmin", "profile::delete"},
	},
}

func applySeed(db *sql.DB, s *store) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, role := range seedData.roles {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO roles(id) VALUES(?)`, role.id); err != nil {
			tx.Rollback()
			return err
		}
		for _, p := range role.parents {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO role_parents(role_id,parent_id) VALUES(?,?)`, role.id, p); err != nil {
				tx.Rollback()
				return err
			}
		}
		if _, exists := s.roles[role.id]; !exists {
			parents := role.parents
			if parents == nil {
				parents = []string{}
			}
			s.roles[role.id] = &roleState{parents: parents, permissions: make(map[string]struct{})}
		}
	}
	for _, a := range seedData.assigns {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO role_permissions(role_id,perm_id) VALUES(?,?)`, a.role, a.perm); err != nil {
			tx.Rollback()
			return err
		}
		if rs, ok := s.roles[a.role]; ok {
			rs.permissions[a.perm] = struct{}{}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.rebuildRBAC()
	return nil
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()

	tx, err := state.db.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	for _, tbl := range []string{"role_permissions", "role_parents", "roles"} {
		if _, err = tx.Exec(`DELETE FROM ` + tbl); err != nil {
			tx.Rollback()
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	state.roles = make(map[string]*roleState)
	if err = applySeed(state.db, state); err != nil {
		http.Error(w, "seed error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := possum.NewResponse(r)
	resp.SetData(map[string]string{"status": "reset"})
	resp.Write(w)
}

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "playground.db"
	}

	db, firstCreate, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	state, err = loadFromDB(db)
	if err != nil {
		log.Fatalf("load db: %v", err)
	}
	if firstCreate {
		if err = applySeed(db, state); err != nil {
			log.Fatalf("seed db: %v", err)
		}
	}

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(err)
	}

	chain := func(h http.HandlerFunc, methods ...string) http.HandlerFunc {
		return possum.Chain(h, possum.Log, possum.Cors(nil), possum.AllowMethods(methods...))
	}

	http.HandleFunc("/api/state", chain(handleState, "GET"))
	http.HandleFunc("/api/roles", chain(handleRoles, "POST"))
	http.HandleFunc("/api/roles/", chain(handleRoleByID, "DELETE", "POST"))
	http.HandleFunc("/api/seed", chain(handleReset, "POST"))
	http.HandleFunc("/api/verify", chain(handleVerify, "POST"))
	http.Handle("/", http.FileServer(http.FS(sub)))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":9080"
	}
	log.Printf("RBAC Playground listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
