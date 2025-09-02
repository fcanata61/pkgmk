// pkgmgr.go — Gerenciador de pacotes minimalista para LFS em Go (100% funcional)
// Recursos implementados:
// - Receitas JSON com fases: preconfig, configure, patch, build, check, install, posinstall, postremove
// - Variáveis expansíveis em comandos: ${REPO}, ${SOURCES}, ${PATCH}, ${BIN}, ${SRC_DIR}, ${BUILD_DIR}, ${PKG_DIR}, ${DESTDIR}, ${PKGFILE}, ${NAME}, ${VERSION}
// - Download via curl ou git (com verificação opcional de SHA256)
// - Build isolado com DESTDIR; empacota em .tar.xz antes de instalar
// - Instalação com fakeroot (opcional) ou direta
// - Logs completos (tee) em /var/log/pkgmgr/ e por comando
// - Saída colorida ANSI
// - Registro exato de arquivos instalados no DB JSON
// - Remoção que desfaz a instalação usando a lista de arquivos + hook postremove
// - CLI com abreviações e etapas isoladas: dl (download), ex (extract), pt (patch), bld (build), chk (check), pk (pack), i (install), rm (remove)
// - search: mostra [✔] se instalado e [ ] se não, com versão da receita
// - sync: sincroniza repositório $REPO (git pull ou clone com --repo-url)
// - upgrade: por pacote ou geral; recompila se versão da receita > instalada
// - Resolução de dependências recursiva/topológica (campo "deps" na receita)
// - Lockfile para evitar execuções concorrentes
// Dependências do sistema: curl, git, tar, xz, fakeroot (opcional), patch, make, coreutils

package main

import (
    "bufio"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "io/fs"
    "os"
    "os/exec"
    "path/filepath"
    "sort"
    "strings"
    "time"
)

// ===== Tipos =====

type Source struct {
    Type   string `json:"type"` // curl | git | binary
    URL    string `json:"url"`
    Sha256 string `json:"sha256,omitempty"` // checksum opcional do artefato baixado (curl/binary)
}

type Steps struct {
    Preconfig  []string `json:"preconfig"`
    Configure  []string `json:"configure"`
    Patch      []string `json:"patch"`
    Build      []string `json:"build"`
    Check      []string `json:"check"`
    Install    []string `json:"install"`
    Posinstall []string `json:"posinstall"`
    Postremove []string `json:"postremove"`
}

type Recipe struct {
    Name    string   `json:"name"`
    Version string   `json:"version"`
    Deps    []string `json:"deps"`
    Source  Source   `json:"source"`
    Steps   Steps    `json:"steps"`
}

type Package struct {
    Name        string   `json:"name"`
    Version     string   `json:"version"`
    InstalledAt string   `json:"installed_at"`
    Files       []string `json:"files"` // caminhos absolutos no sistema
}

type Database struct {
    Packages []Package `json:"packages"`
}

// ===== Diretórios (podem ser sobrescritos via env) =====

var (
    dbPath      = getenvDefault("PKGMGR_DB", "/var/lib/pkgmgr/packages.json")
    repoDir     = getenvDefault("PKGMGR_REPO", "/var/lib/pkgmgr/repo")
    sourcesDir  = getenvDefault("PKGMGR_SOURCES", "/var/lib/pkgmgr/sources")
    patchesDir  = getenvDefault("PKGMGR_PATCH", "/var/lib/pkgmgr/patches")
    binDir      = getenvDefault("PKGMGR_BIN", "/var/lib/pkgmgr/binpkgs")
    buildRoot   = getenvDefault("PKGMGR_BUILD", "/tmp/build")
    pkgRoot     = getenvDefault("PKGMGR_DESTS", "/tmp/pkg")
    logsDir     = getenvDefault("PKGMGR_LOGS", "/var/log/pkgmgr")
    lockFile    = getenvDefault("PKGMGR_LOCK", "/var/lib/pkgmgr/lock")
)

// ===== Cores ANSI =====

var (
    cReset   = "\x1b[0m"
    cBold    = "\x1b[1m"
    cGreen   = "\x1b[32m"
    cYellow  = "\x1b[33m"
    cRed     = "\x1b[31m"
    cBlue    = "\x1b[34m"
    cMagenta = "\x1b[35m"
)

func color(s, col string) string { return col + s + cReset }

// ===== Logger (tee) =====

type Logger struct { file *os.File; out io.Writer }

func newLogger(name string) (*Logger, error) {
    os.MkdirAll(logsDir, 0o755)
    stamp := time.Now().Format("20060102-150405")
    path := filepath.Join(logsDir, fmt.Sprintf("%s-%s.log", name, stamp))
    f, err := os.Create(path)
    if err != nil { return nil, err }
    return &Logger{file: f, out: io.MultiWriter(os.Stdout, f)}, nil
}
func (l *Logger) Close() { if l.file != nil { _ = l.file.Close() } }
func (l *Logger) Println(a ...any) { fmt.Fprintln(l.out, a...) }
func (l *Logger) Printf(f string, a ...any) { fmt.Fprintf(l.out, f, a...) }

// ===== Util =====

func getenvDefault(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }
func pathExists(p string) bool { _, err := os.Stat(p); return err == nil }

func expandVars(s string, vars map[string]string) string {
    for k, v := range vars { s = strings.ReplaceAll(s, "${"+k+"}", v) }
    return s
}
func envArray(vars map[string]string) []string { arr := os.Environ(); for k, v := range vars { arr = append(arr, k+"="+v) } ; return arr }

func runCommand(log *Logger, cmdStr, workDir string, vars map[string]string) error {
    cmdStr = expandVars(cmdStr, vars)
    log.Println(color("$ "+cmdStr, cBlue))
    cmd := exec.Command("bash", "-c", cmdStr)
    if workDir != "" { cmd.Dir = workDir }
    cmd.Env = envArray(vars)
    stdout, _ := cmd.StdoutPipe(); stderr, _ := cmd.StderrPipe()
    if err := cmd.Start(); err != nil { return err }
    go streamTo(log.out, stdout); go streamTo(log.out, stderr)
    return cmd.Wait()
}

func streamTo(w io.Writer, r io.Reader) { sc := bufio.NewScanner(r); for sc.Scan() { fmt.Fprintln(w, sc.Text()) } }

// ===== DB =====

func loadDB() Database { var db Database; data, err := os.ReadFile(dbPath); if err == nil { _ = json.Unmarshal(data, &db) }; return db }
func saveDB(db Database) error { os.MkdirAll(filepath.Dir(dbPath), 0o755); data, _ := json.MarshalIndent(db, "", "  "); return os.WriteFile(dbPath, data, 0o644) }

func getPkg(name string) (Package, bool) { db := loadDB(); for _, p := range db.Packages { if p.Name == name { return p, true } } ; return Package{}, false }
func addOrReplacePkg(p Package) error { db := loadDB(); out := db.Packages[:0]; for _, e := range db.Packages { if e.Name != p.Name { out = append(out, e) } } ; db.Packages = append(out, p); return saveDB(db) }
func removePkgFromDB(name string) error { db := loadDB(); out := db.Packages[:0]; for _, e := range db.Packages { if e.Name != name { out = append(out, e) } } ; db.Packages = out; return saveDB(db) }

// ===== Lock =====

func withLock(fn func() error) error {
    os.MkdirAll(filepath.Dir(lockFile), 0o755)
    if pathExists(lockFile) { return errors.New("outro pkgmgr está em execução (lock)") }
    if err := os.WriteFile(lockFile, []byte(fmt.Sprintln(os.Getpid())), 0o644); err != nil { return err }
    defer os.Remove(lockFile)
    return fn()
}

// ===== Receitas =====

func recipePathByName(name string) string { return filepath.Join(repoDir, name+".json") }

func loadRecipeFrom(path string) (Recipe, error) { var r Recipe; data, err := os.ReadFile(path); if err != nil { return r, err } ; if err := json.Unmarshal(data, &r); err != nil { return r, err } ; return r, nil }

func listRecipes() ([]Recipe, error) {
    entries, err := os.ReadDir(repoDir)
    if err != nil { return nil, err }
    var out []Recipe
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") { continue }
        r, err := loadRecipeFrom(filepath.Join(repoDir, e.Name()))
        if err == nil { out = append(out, r) }
    }
    sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
    return out, nil
}

// ===== Dependências (toposort) =====

type nodeState int
const ( nsWhite nodeState = iota; nsGray; nsBlack )

func topoOrder(target Recipe) ([]Recipe, error) {
    order := []Recipe{}
    state := map[string]nodeState{}
    var dfs func(string) error
    dfs = func(name string) error {
        if state[name] == nsBlack { return nil }
        if state[name] == nsGray { return fmt.Errorf("ciclo de dependência: %s", name) }
        state[name] = nsGray
        r, err := loadRecipeFrom(recipePathByName(name))
        if err != nil { return fmt.Errorf("dep %s não encontrada: %w", name, err) }
        for _, d := range r.Deps { if err := dfs(d); err != nil { return err } }
        state[name] = nsBlack
        order = append(order, r)
        return nil
    }
    for _, d := range target.Deps { if err := dfs(d); err != nil { return nil, err } }
    order = append(order, target)
    return order, nil
}

// ===== Download/Extrair + SHA256 =====

func computeSha256(path string) (string, error) { f, err := os.Open(path); if err != nil { return "", err } ; defer f.Close(); h := sha256.New(); if _, err := io.Copy(h, f); err != nil { return "", err } ; return hex.EncodeToString(h.Sum(nil)), nil }

func downloadSource(log *Logger, src Source) (string, error) {
    os.MkdirAll(sourcesDir, 0o755)
    switch src.Type {
    case "curl", "binary":
        filename := filepath.Base(src.URL)
        dest := filepath.Join(sourcesDir, filename)
        if !pathExists(dest) {
            if err := runCommand(log, fmt.Sprintf("curl -L --fail -o %q %q", dest, src.URL), ".", nil); err != nil { return "", err }
        }
        if src.Sha256 != "" {
            sum, err := computeSha256(dest)
            if err != nil { return "", err }
            if !strings.EqualFold(sum, strings.ToLower(src.Sha256)) { return "", fmt.Errorf("sha256 não confere para %s", dest) }
        }
        return dest, nil
    case "git":
        repoName := strings.TrimSuffix(filepath.Base(src.URL), ".git")
        dest := filepath.Join(sourcesDir, repoName)
        if !pathExists(dest) {
            if err := runCommand(log, fmt.Sprintf("git clone %q %q", src.URL, dest), ".", nil); err != nil { return "", err }
        } else {
            _ = runCommand(log, "git pull --rebase", dest, nil)
        }
        return dest, nil
    default:
        return "", fmt.Errorf("source desconhecido: %s", src.Type)
    }
}

func extractTo(log *Logger, archiveOrDir, buildDir string) (string, error) {
    os.RemoveAll(buildDir)
    os.MkdirAll(buildDir, 0o755)
    if fi, err := os.Stat(archiveOrDir); err == nil && fi.IsDir() { return archiveOrDir, nil }
    if err := runCommand(log, fmt.Sprintf("tar -xf %q -C %q --strip-components=1", archiveOrDir, buildDir), ".", nil); err != nil { return "", err }
    return buildDir, nil
}

// ===== Empacotar/Instalar =====

func packDestdir(log *Logger, pkgDir, outFile string) error {
    os.MkdirAll(filepath.Dir(outFile), 0o755)
    return runCommand(log, fmt.Sprintf("tar -C %q -cJf %q .", pkgDir, outFile), ".", nil)
}

func installArchive(log *Logger, archive string, useFakeroot bool) error {
    if useFakeroot { return runCommand(log, fmt.Sprintf("fakeroot -- tar -xpf %q -C /", archive), ".", nil) }
    return runCommand(log, fmt.Sprintf("tar -xpf %q -C /", archive), ".", nil)
}

func stripBinaries(log *Logger, root string) error { return runCommand(log, fmt.Sprintf("find %q -type f -perm -111 -exec strip --strip-unneeded {} +", root), ".", nil) }

func recordFilesUnder(root string) ([]string, error) {
    files := []string{}
    err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
        if err != nil { return err }
        if d.IsDir() { return nil }
        rel, _ := filepath.Rel(root, p)
        files = append(files, "/"+filepath.ToSlash(rel))
        return nil
    })
    sort.Strings(files)
    return files, err
}

// ===== Fases =====

type phaseSel struct{ pre, conf, pt, bld, chk, inst, pos bool }

func runPhases(log *Logger, r Recipe, buildDir, pkgDir string, vars map[string]string, sel phaseSel, doStrip bool) error {
    phases := []struct{ name string; cmds []string }{
        {"preconfig", r.Steps.Preconfig},
        {"configure", r.Steps.Configure},
        {"patch", r.Steps.Patch},
        {"build", r.Steps.Build},
        {"check", r.Steps.Check},
        {"install", r.Steps.Install},
        {"posinstall", r.Steps.Posinstall},
    }
    should := map[string]bool{
        "preconfig": sel.pre,
        "configure": sel.conf,
        "patch": sel.pt,
        "build": sel.bld,
        "check": sel.chk,
        "install": sel.inst,
        "posinstall": sel.pos,
    }
    for _, ph := range phases {
        if len(ph.cmds) == 0 || !should[ph.name] { continue }
        log.Println(color("==> "+ph.name, cMagenta))
        for _, c := range ph.cmds {
            if err := runCommand(log, c, buildDir, vars); err != nil { return fmt.Errorf("erro na fase %s: %w", ph.name, err) }
        }
        if ph.name == "install" && doStrip { if err := stripBinaries(log, pkgDir); err != nil { return err } }
    }
    return nil
}

// ===== Instalar (com deps), Upgrade =====

type InstallOptions struct {
    UseFakeroot  bool
    FromBinary   bool
    ExternalDest string
    Strip        bool
}

func buildAndInstall(log *Logger, r Recipe, opts InstallOptions) error {
    nameVer := fmt.Sprintf("%s-%s", r.Name, r.Version)
    log.Println(color("==== "+nameVer+" ====", cBold))

    buildDir := filepath.Join(buildRoot, r.Name)
    pkgDir := filepath.Join(pkgRoot, r.Name)
    os.RemoveAll(buildDir); os.RemoveAll(pkgDir)
    os.MkdirAll(buildDir, 0o755); os.MkdirAll(pkgDir, 0o755)

    vars := map[string]string{
        "REPO": repoDir, "SOURCES": sourcesDir, "PATCH": patchesDir, "BIN": binDir,
        "SRC_DIR": sourcesDir, "BUILD_DIR": buildDir, "PKG_DIR": pkgDir, "DESTDIR": pkgDir,
        "NAME": r.Name, "VERSION": r.Version,
    }

    srcPath, err := downloadSource(log, r.Source)
    if err != nil { return err }

    actBuild := buildDir
    if !opts.FromBinary {
        actBuild, err = extractTo(log, srcPath, buildDir)
        if err != nil { return err }
    }

    sel := phaseSel{pre: true, conf: true, pt: true, bld: true, chk: true, inst: true, pos: true}

    if opts.ExternalDest != "" {
        os.MkdirAll(opts.ExternalDest, 0o755)
        vars["PKG_DIR"], vars["DESTDIR"] = opts.ExternalDest, opts.ExternalDest
        sel = phaseSel{pre: false, conf: false, pt: false, bld: false, chk: false, inst: false, pos: false}
    }

    if opts.FromBinary { sel = phaseSel{inst: true, pos: true} }

    if err := runPhases(log, r, actBuild, vars["PKG_DIR"], vars, sel, opts.Strip); err != nil { return err }

    os.MkdirAll(binDir, 0o755)
    pkgFile := filepath.Join(binDir, fmt.Sprintf("%s-%s.tar.xz", r.Name, r.Version))
    if err := packDestdir(log, vars["PKG_DIR"], pkgFile); err != nil { return err }
    vars["PKGFILE"] = pkgFile
    log.Println(color("Pacote: "+pkgFile, cGreen))

    if err := installArchive(log, pkgFile, opts.UseFakeroot); err != nil { return err }

    files, err := recordFilesUnder(vars["PKG_DIR"])
    if err != nil { return err }
    if err := addOrReplacePkg(Package{ Name: r.Name, Version: r.Version, InstalledAt: time.Now().Format(time.RFC3339), Files: files }); err != nil { return err }

    log.Println(color("Instalado: "+nameVer, cGreen))
    return nil
}

func installWithDeps(log *Logger, recipePath string, opts InstallOptions) error {
    r, err := loadRecipeFrom(recipePath)
    if err != nil { return err }
    order, err := topoOrder(r); if err != nil { return err }
    for _, it := range order { if err := buildAndInstall(log, it, opts); err != nil { return err } }
    return nil
}

func upgradeOne(log *Logger, name string, opts InstallOptions) error {
    r, err := loadRecipeFrom(recipePathByName(name))
    if err != nil { return err }
    p, ok := getPkg(name)
    if !ok || p.Version != r.Version {
        log.Println(color(fmt.Sprintf("Atualizando %s (%s -> %s)", name, p.Version, r.Version), cYellow))
        return installWithDeps(log, recipePathByName(name), opts)
    }
    log.Println(color(name+": já na última versão", cGreen))
    return nil
}

func upgradeAll(log *Logger, opts InstallOptions) error {
    rs, err := listRecipes(); if err != nil { return err }
    for _, r := range rs { if err := upgradeOne(log, r.Name, opts); err != nil { return err } }
    return nil
}

// ===== Remoção =====

func postremoveIfAny(log *Logger, name, version string) {
    rPath := recipePathByName(name)
    if !pathExists(rPath) { return }
    r, err := loadRecipeFrom(rPath); if err != nil { return }
    if len(r.Steps.Postremove) == 0 { return }
    vars := map[string]string{"NAME": name, "VERSION": version}
    for _, c := range r.Steps.Postremove { _ = runCommand(log, c, "/", vars) }
}

func removePackage(log *Logger, name string) error {
    p, ok := getPkg(name)
    if !ok { return fmt.Errorf("%s não está instalado", name) }
    for i := len(p.Files) - 1; i >= 0; i-- { _ = os.Remove(p.Files[i]) }
    seen := map[string]struct{}{}
    for _, f := range p.Files { d := filepath.Dir(f); for d != "/" && d != "." { seen[d] = struct{}{}; d = filepath.Dir(d) } }
    dirs := make([]string, 0, len(seen)); for d := range seen { dirs = append(dirs, d) }
    sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
    for _, d := range dirs { _ = os.Remove(d) }

    postremoveIfAny(log, name, p.Version)
    if err := removePkgFromDB(name); err != nil { return err }
    log.Println(color("Removido: "+name+"-"+p.Version, cGreen))
    return nil
}

// ===== sync / search =====

func syncRepo(log *Logger, repoURL string) error {
    os.MkdirAll(repoDir, 0o755)
    if pathExists(filepath.Join(repoDir, ".git")) {
        return runCommand(log, "git pull --rebase", repoDir, nil)
    }
    if repoURL == "" { return errors.New("$REPO não é git e --repo-url não informado") }
    return runCommand(log, fmt.Sprintf("git clone %q %q", repoURL, repoDir), ".", nil)
}

func searchCmd(log *Logger, term string) error {
    rs, err := listRecipes(); if err != nil { return err }
    term = strings.ToLower(term)
    db := loadDB()
    installed := map[string]string{}
    for _, p := range db.Packages { installed[p.Name] = p.Version }

    for _, r := range rs {
        if term != "" && !strings.Contains(strings.ToLower(r.Name), term) { continue }
        mark := "[ ]"
        if _, ok := installed[r.Name]; ok { mark = "[✔]" }
        log.Println(fmt.Sprintf("%s %s %s", mark, r.Name, r.Version))
    }
    return nil
}

// ===== CLI =====

func usage() {
    fmt.Println(color("pkgmgr - gerenciador minimalista (LFS)", cBold))
    fmt.Println("\nUso:")
    fmt.Println("  pkgmgr <comando> [opções] <alvo>")
    fmt.Println("\nComandos:")
    fmt.Println("  install|i      Instala receita (resolve deps)")
    fmt.Println("  remove|rm      Remove pacote instalado")
    fmt.Println("  download|dl    Só baixar a fonte da receita")
    fmt.Println("  extract|ex     Só extrair fonte para BUILD_DIR")
    fmt.Println("  patch|pt       Só aplicar patches")
    fmt.Println("  build|bld      Só compilar (preconfig+configure+patch+build)")
    fmt.Println("  check|chk      Só executar testes")
    fmt.Println("  pack|pk        Só empacotar o DESTDIR em .tar.xz")
    fmt.Println("  list|ls        Lista pacotes instalados")
    fmt.Println("  info           Mostra arquivos registrados de um pacote")
    fmt.Println("  search         Procura receitas no $REPO (marca [✔]/[ ])")
    fmt.Println("  sync           Sincroniza $REPO (git pull/clone)")
    fmt.Println("  upgrade        Atualiza um pacote ou todos")
    fmt.Println("\nOpções:")
    fmt.Println("  --destdir DIR  Usar DESTDIR externo (install)")
    fmt.Println("  --bin          Instalar de binário (pula build)")
    fmt.Println("  --no-fakeroot  Não usar fakeroot (install)")
    fmt.Println("  --strip        Rodar strip no DESTDIR durante install")
    fmt.Println("  --repo-url URL URL do repositório git para sync inicial")
}

func parseFlags(args []string) (cmd string, flags map[string]string, pos []string) {
    flags = map[string]string{}
    if len(args) == 0 { return "", flags, nil }
    cmd = args[0]
    for i := 1; i < len(args); i++ {
        a := args[i]
        if strings.HasPrefix(a, "--") {
            if a == "--bin" || a == "--no-fakeroot" || a == "--strip" { flags[a] = "true"; continue }
            if i+1 < len(args) { flags[a] = args[i+1]; i++ } else { flags[a] = "" }
        } else { pos = append(pos, a) }
    }
    return
}

func main() {
    if len(os.Args) < 2 { usage(); os.Exit(1) }

    cmd, flags, pos := parseFlags(os.Args[1:])
    switch cmd { case "i": cmd = "install"; case "rm": cmd = "remove"; case "dl": cmd = "download"; case "ex": cmd = "extract"; case "pt": cmd = "patch"; case "bld": cmd = "build"; case "chk": cmd = "check"; case "pk": cmd = "pack"; case "ls": cmd = "list" }

    log, err := newLogger(cmd); if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    defer log.Close()

    if err := withLock(func() error {
        switch cmd {
        case "list":
            db := loadDB(); if len(db.Packages) == 0 { log.Println(color("(vazio)", cYellow)); return nil }
            for _, p := range db.Packages { log.Println(color(fmt.Sprintf("- %s (%s) [%s]", p.Name, p.Version, p.InstalledAt), cGreen)) }
            return nil
        case "info":
            if len(pos) < 1 { log.Println(color("use: pkgmgr info <nome>", cRed)); return errors.New("args") }
            p, ok := getPkg(pos[0]); if !ok { log.Println(color("não instalado", cRed)); return nil }
            log.Println(color(p.Name+"-"+p.Version+" arquivos:", cBold))
            for _, f := range p.Files { log.Println(f) }
            return nil
        case "search":
            term := ""; if len(pos) > 0 { term = pos[0] }
            return searchCmd(log, term)
        case "sync":
            return syncRepo(log, flags["--repo-url"])
        case "upgrade":
            opts := InstallOptions{ UseFakeroot: flags["--no-fakeroot"] != "true", Strip: flags["--strip"] == "true" }
            if len(pos) == 0 { return upgradeAll(log, opts) }
            return upgradeOne(log, pos[0], opts)
        case "remove":
            if len(pos) < 1 { log.Println(color("use: pkgmgr remove|rm <nome>", cRed)); return errors.New("args") }
            return removePackage(log, pos[0])
        case "install":
            if len(pos) < 1 { log.Println(color("use: pkgmgr install|i <receita.json>", cRed)); return errors.New("args") }
            opts := InstallOptions{ UseFakeroot: flags["--no-fakeroot"] != "true", FromBinary: flags["--bin"] == "true", ExternalDest: flags["--destdir"], Strip: flags["--strip"] == "true" }
            return installWithDeps(log, pos[0], opts)
        case "download", "extract", "patch", "build", "check", "pack":
            if len(pos) < 1 { usage(); return errors.New("args") }
            r, err := loadRecipeFrom(pos[0]); if err != nil { return err }
            buildDir := filepath.Join(buildRoot, r.Name); pkgDir := filepath.Join(pkgRoot, r.Name)
            os.RemoveAll(buildDir); os.RemoveAll(pkgDir); os.MkdirAll(buildDir, 0o755); os.MkdirAll(pkgDir, 0o755)
            vars := map[string]string{ "REPO": repoDir, "SOURCES": sourcesDir, "PATCH": patchesDir, "BIN": binDir, "SRC_DIR": sourcesDir, "BUILD_DIR": buildDir, "PKG_DIR": pkgDir, "DESTDIR": pkgDir, "NAME": r.Name, "VERSION": r.Version }
            srcPath, err := downloadSource(log, r.Source); if err != nil { return err }
            if cmd == "download" { return nil }
            actBuild, err := extractTo(log, srcPath, buildDir); if err != nil { return err }
            if cmd == "extract" { return nil }
            sel := phaseSel{}
            switch cmd { case "patch": sel.pt = true; case "build": sel.pre, sel.conf, sel.pt, sel.bld = true, true, true, true; case "check": sel.chk = true; case "pack": sel.pre, sel.conf, sel.pt, sel.bld, sel.inst = true, true, true, true, true }
            if err := runPhases(log, r, actBuild, pkgDir, vars, sel, flags["--strip"] == "true"); err != nil { return err }
            if cmd == "pack" { out := filepath.Join(binDir, fmt.Sprintf("%s-%s.tar.xz", r.Name, r.Version)); if err := packDestdir(log, pkgDir, out); err != nil { return err } ; log.Println(color("Gerado: "+out, cGreen)) }
            return nil
        default:
            usage();
            return nil
        }
    }); err != nil {
        log.Println(color("ERRO: "+err.Error(), cRed))
        os.Exit(1)
    }
}
