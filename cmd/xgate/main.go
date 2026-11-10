// Command xgate builds a gateway binary with selected compile-time modules.
// It is the gateway's analogue of xcaddy: generate a main package with blank
// imports, resolve modules, and run go build.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const version = "0.2.0"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "build":
		buildCmd(os.Args[2:])
	case "list":
		listCmd(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("xgate %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "xgate: unknown command %q\n", os.Args[1])
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `xgate — build a gateway with compile-time modules.

Usage:
  xgate build [flags]
  xgate list --manifest <file>
  xgate version

Build flags:
  --src <dir>         gateway source root (default ".")
  --output <file>     output binary (default "xgate-gateway")
  --manifest <file>   YAML manifest with modules
  --with <spec>       module[@version][=replacement]; repeatable
  --lock <file>       lock file (default "xgate.lock" with --manifest)
  --no-lock           do not write a lock file
  --tags <tags>       extra go build tags
  --keep              keep the temporary build directory
`)
	os.Exit(2)
}

func buildCmd(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	src := fs.String("src", "", "gateway source root")
	output := fs.String("output", "", "output binary")
	manifestPath := fs.String("manifest", "", "YAML manifest with modules")
	lockPath := fs.String("lock", "", "lock file")
	noLock := fs.Bool("no-lock", false, "do not write a lock file")
	tags := fs.String("tags", "", "extra go build tags")
	keep := fs.Bool("keep", false, "keep temporary build directory")
	var with stringList
	fs.Var(&with, "with", "module[@version][=replacement]")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "xgate: unexpected arguments: %v\n", fs.Args())
		os.Exit(2)
	}

	var mf *Manifest
	if *manifestPath != "" {
		var err error
		mf, err = loadManifest(*manifestPath)
		if err != nil {
			fatal(err)
		}
		if *src == "" {
			*src = mf.Gateway.Source
		}
		if *output == "" {
			*output = mf.Gateway.Output
		}
	}
	if *src == "" {
		*src = "."
	}
	if *output == "" {
		*output = "xgate-gateway"
	}

	var mods []moduleSpec
	if mf != nil {
		baseDir := filepath.Dir(*manifestPath)
		for _, m := range mf.Modules {
			spec, err := specFromManifest(m, baseDir)
			if err != nil {
				fatal(err)
			}
			mods = append(mods, spec)
		}
	}
	cliMods, err := parseSpecs(with)
	if err != nil {
		fatal(err)
	}
	mods, err = mergeSpecs(mods, cliMods)
	if err != nil {
		fatal(err)
	}

	root, module, err := moduleRoot(*src)
	if err != nil {
		fatal(err)
	}
	var lock string
	if mf != nil && !*noLock {
		lock = *lockPath
		if lock == "" {
			lock = "xgate.lock"
		}
	}
	if err := build(root, module, *output, mods, *tags, *keep, lock); err != nil {
		fatal(err)
	}
}

func build(root, module, output string, mods []moduleSpec, tags string, keep bool, lockPath string) error {
	dir, err := os.MkdirTemp("", "xgate-build-*")
	if err != nil {
		return err
	}
	if !keep {
		defer os.RemoveAll(dir)
	} else {
		fmt.Printf("xgate: build directory: %s\n", dir)
	}

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(renderMain(module, mods)), 0o644); err != nil {
		return err
	}
	goVersion, err := moduleGoVersion(root)
	if err != nil {
		return err
	}
	gomod := fmt.Sprintf("module xgate-build\n\ngo %s\n\nrequire %s v0.0.0\n\nreplace %s => %s\n",
		goVersion, module, module, root)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		return err
	}

	for _, m := range mods {
		if m.Replacement != "" {
			if err := run(dir, "go", "mod", "edit", "-replace", m.Path+"="+m.Replacement); err != nil {
				return err
			}
		}
		if m.Version != "" {
			if err := run(dir, "go", "get", m.Path+"@"+m.Version); err != nil {
				return err
			}
		}
	}
	if err := run(dir, "go", "mod", "tidy"); err != nil {
		return err
	}

	out, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	args := []string{"build", "-trimpath", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ".")
	if err := run(dir, "go", args...); err != nil {
		return err
	}
	fmt.Printf("xgate: built %s\n", out)
	for _, m := range mods {
		fmt.Printf("  module %s %s\n", m.Path, m.Version)
	}
	if lockPath != "" {
		deps, err := collectDeps(dir)
		if err != nil {
			return err
		}
		if err := writeLock(lockPath, root, module, mods, deps); err != nil {
			return err
		}
		fmt.Printf("xgate: lock %s\n", lockPath)
	}
	return nil
}

// Manifest is the reproducible build description.
type Manifest struct {
	Gateway struct {
		Source string `yaml:"source"`
		Output string `yaml:"output"`
	} `yaml:"gateway"`
	Modules []ManifestModule `yaml:"modules"`
}

type ManifestModule struct {
	Path        string `yaml:"path"`
	Version     string `yaml:"version"`
	Replacement string `yaml:"replacement"`
}

func loadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mf Manifest
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	for i, m := range mf.Modules {
		if strings.TrimSpace(m.Path) == "" {
			return nil, fmt.Errorf("manifest %s: modules[%d].path is required", path, i)
		}
	}
	return &mf, nil
}

func specFromManifest(m ManifestModule, baseDir string) (moduleSpec, error) {
	spec := moduleSpec{Path: strings.TrimSpace(m.Path), Version: strings.TrimSpace(m.Version)}
	if m.Replacement != "" {
		repl := m.Replacement
		if !filepath.IsAbs(repl) {
			repl = filepath.Join(baseDir, repl)
		}
		abs, err := filepath.Abs(repl)
		if err != nil {
			return moduleSpec{}, err
		}
		spec.Replacement = abs
	}
	return spec, nil
}

func mergeSpecs(existing, extra []moduleSpec) ([]moduleSpec, error) {
	seen := make(map[string]bool, len(existing)+len(extra))
	out := make([]moduleSpec, 0, len(existing)+len(extra))
	for _, m := range append(existing, extra...) {
		if seen[m.Path] {
			return nil, fmt.Errorf("duplicate module %q", m.Path)
		}
		seen[m.Path] = true
		out = append(out, m)
	}
	return out, nil
}

func writeLock(path, root, module string, mods, deps []moduleSpec) error {
	lock := struct {
		SourceSHA    string       `yaml:"source_sha"`
		Gateway      string       `yaml:"gateway"`
		Modules      []moduleSpec `yaml:"modules"`
		Dependencies []moduleSpec `yaml:"dependencies"`
	}{
		SourceSHA:    sourceSHA(root),
		Gateway:      module,
		Modules:      mods,
		Dependencies: deps,
	}
	data, err := yaml.Marshal(lock)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte("# generated by xgate\n"), data...), 0o644)
}

func collectDeps(dir string) ([]moduleSpec, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m all: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	deps := make([]moduleSpec, 0, 32)
	for {
		var m struct {
			Path    string
			Version string
			Replace *struct {
				Path    string
				Version string
			}
		}
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if m.Path == "xgate-build" {
			continue
		}
		dep := moduleSpec{Path: m.Path, Version: m.Version}
		if m.Replace != nil {
			dep.Replacement = m.Replace.Path
			if m.Replace.Version != "" {
				dep.Version = m.Replace.Version
			}
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

func sourceSHA(root string) string {
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func listCmd(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	manifestPath := fs.String("manifest", "xgate.yaml", "YAML manifest with modules")
	lockPath := fs.String("lock", "", "lock file (default xgate.lock)")
	_ = fs.Parse(args)
	mf, err := loadManifest(*manifestPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("gateway %s\n", mf.Gateway.Source)
	for _, m := range mf.Modules {
		fmt.Printf("  module %s %s\n", m.Path, m.Version)
	}
	lock := *lockPath
	if lock == "" {
		lock = "xgate.lock"
	}
	if data, err := os.ReadFile(lock); err == nil {
		var resolved struct {
			Modules      []moduleSpec `yaml:"modules"`
			Dependencies []moduleSpec `yaml:"dependencies"`
		}
		if yaml.Unmarshal(data, &resolved) == nil {
			for _, m := range resolved.Modules {
				fmt.Printf("  locked %s %s\n", m.Path, m.Version)
			}
			fmt.Printf("  dependencies %d\n", len(resolved.Dependencies))
		}
	}
}

type moduleSpec struct {
	Path        string `yaml:"path"`
	Version     string `yaml:"version,omitempty"`
	Replacement string `yaml:"replacement,omitempty"`
}

func parseSpecs(specs []string) ([]moduleSpec, error) {
	out := make([]moduleSpec, 0, len(specs))
	for _, raw := range specs {
		m, err := parseSpec(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func parseSpec(raw string) (moduleSpec, error) {
	left, replacement, _ := strings.Cut(raw, "=")
	if left == "" {
		return moduleSpec{}, fmt.Errorf("empty --with module")
	}
	path, version := left, ""
	if i := strings.LastIndex(left, "@"); i >= 0 {
		path, version = left[:i], left[i+1:]
	}
	if path == "" {
		return moduleSpec{}, fmt.Errorf("invalid --with %q", raw)
	}
	if replacement != "" {
		abs, err := filepath.Abs(replacement)
		if err != nil {
			return moduleSpec{}, err
		}
		replacement = abs
	}
	return moduleSpec{Path: path, Version: version, Replacement: replacement}, nil
}

func renderMain(module string, mods []moduleSpec) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n")
	fmt.Fprintf(&b, "\t%q\n", module+"/pkg/app")
	fmt.Fprintf(&b, "\t_ %q\n", module+"/plugins/standard")
	for _, m := range mods {
		fmt.Fprintf(&b, "\t_ %q\n", m.Path)
	}
	b.WriteString(")\n\nfunc main() {\n\tapp.Main()\n}\n")
	return b.String()
}

func moduleRoot(src string) (string, string, error) {
	dir, err := filepath.Abs(src)
	if err != nil {
		return "", "", err
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					return dir, strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
				}
			}
			return "", "", fmt.Errorf("%s/go.mod has no module directive", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("go.mod not found above %s", src)
		}
		dir = parent
	}
}

func moduleGoVersion(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go ")), nil
		}
	}
	return "1.26", nil
}

func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "xgate: %v\n", err)
	os.Exit(1)
}
