// Package meta reads and interprets repo metadata (acyl.yml)
package meta

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dollarshaveclub/acyl/pkg/eventlogger"
	"github.com/dollarshaveclub/acyl/pkg/ghclient"
	"github.com/dollarshaveclub/acyl/pkg/match"
	"github.com/dollarshaveclub/acyl/pkg/models"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	billy "gopkg.in/src-d/go-billy.v4"
	yaml "gopkg.in/yaml.v2"
)

// Getter describes an object that fetches and parses metadata (acyl.yml) from a set of repositories
type Getter interface {
	Get(ctx context.Context, rd models.RepoRevisionData) (*models.RepoConfig, error)
	FetchCharts(ctx context.Context, rc *models.RepoConfig, basePath string) (ChartLocations, error)
	GetAcylYAML(ctx context.Context, rc *models.RepoConfig, repo, ref string) (err error)
}

var _ Getter = &DataGetter{}

// DataGetter is an object that fetches and parses metadata (acyl.yml) from a set of repositories
type DataGetter struct {
	// RepoRefOverrides is a map for reponame to ref override (primarily for local development)
	RepoRefOverrides map[string]string
	RC               ghclient.RepoClient
	FS               billy.Filesystem
}

func log(ctx context.Context, msg string, args ...interface{}) {
	eventlogger.GetLogger(ctx).Printf(msg, args...)
}

// User errors
var (
	ErrYAMLSyntax              = errors.New("error unmarshaling YAML")
	ErrEmptyArg                = errors.New("empty argument")
	ErrUnsupportedVersion      = errors.New("acyl.yml is previous or unsupported version")
	ErrNilParent               = errors.New("parent is nil")
	ErrNilAncestor             = errors.New("ancestor is nil")
	ErrNilDependency           = errors.New("dependency is nil")
	ErrMissingPath             = errors.New("repo dependency lacks ChartPath/ChartRepoPath")
	ErrMultipleDependency      = errors.New("dependency error: %v: only one of Repo, ChartPath, or ChartRepoPath may be used")
	ErrDuplicateDependency     = errors.New("duplicate repository dependency (check for circular dependency declarations)")
	ErrBranchAndRepo           = errors.New("branch matching and default branch not available if ChartPath or ChartRepoPath is used")
	ErrValidateDependencyNames = errors.New("error validating dependency names")
	ErrMalformedValueOverride  = errors.New("malformed value override")
	ErrMalformedRepoPath       = errors.New("malformed repo path")
)

// System errors
var (
	ErrGetFileContents      = errors.New("error getting file contents")
	ErrGetDirectoryContents = errors.New("error getting directory contents")
	ErrGetRepoBranches      = errors.New("error getting repo branches")
	ErrGetRefForRepo        = errors.New("error getting ref for repo")
	ErrCreatingDirectory    = errors.New("error creating directory")
	ErrCreatingSymlink      = errors.New("error creating symlink")
	ErrCreatingFile         = errors.New("error creating file")
	ErrWritingFile          = errors.New("error writing to file")
	ErrShortWrite           = io.ErrShortWrite
	ErrNilLocation          = errors.New("location is nil")
	ErrGetChartName         = errors.New("error getting chart name for dependency")
)

var ErrContextCancelled = errors.New("context was cancelled")

// GetAcylYAML fetches acyl.yaml from repo at ref and deserializes it into rc, returning an error if the version is < 2.
func (g DataGetter) GetAcylYAML(ctx context.Context, rc *models.RepoConfig, repo, ref string) (err error) {
	defer func() {
		if err != nil {
			log(ctx, "error in acyl.yml for %v@%v: %v", repo, ref, err)
		}
	}()
	log(ctx, "fetching acyl.yml for %v@%v", repo, ref)
	b, err := g.RC.GetFileContents(ctx, repo, "acyl.yml", ref)
	if err != nil {
		return fmt.Errorf("error getting %v@%v: %v: %w", repo, ref, "acyl.yml", ErrGetFileContents)
	}
	if err := yaml.Unmarshal(b, &rc); err != nil {
		return ErrYAMLSyntax
	}
	if rc.Version < 2 {
		return fmt.Errorf("unsupported version %d: %w", rc.Version, ErrUnsupportedVersion)
	}
	rc.Application.SetValueDefaults()
	rc.Application.Repo = repo
	rc.Application.Ref = ref
	return nil
}

func (g DataGetter) getChartName(ctx context.Context, repo, ref, path string) (_ string, err error) {
	defer func() {
		if err != nil {
			log(ctx, "error getting chart name for %v@%v:%v: %v", repo, ref, path, err)
		}
	}()
	if repo == "" || ref == "" || path == "" {
		return "", fmt.Errorf("empty repo (%v), ref (%v) or path (%v): %w", repo, ref, path, ErrEmptyArg)
	}
	log(ctx, "getting file contents: %v@%v: %v", repo, ref, path+"/Chart.yaml")
	b, err := g.RC.GetFileContents(ctx, repo, path+"/Chart.yaml", ref)
	if err != nil {
		return "", fmt.Errorf("error getting file contents from %v@%v: %v: %w", repo, ref, path+"/Chart.yaml", ErrGetFileContents)
	}
	cd := struct {
		Name string `yaml:"name"`
	}{}
	if err := yaml.Unmarshal(b, &cd); err != nil {
		return "", fmt.Errorf("error unmarshaling Chart.yaml: %v: %w", err, ErrYAMLSyntax)
	}
	if cd.Name == "" {
		return "", fmt.Errorf("chart name field is empty: %w", ErrEmptyArg)
	}
	return cd.Name, nil
}

func (g DataGetter) getDependencyChartName(ctx context.Context, d *models.RepoConfigDependency) (cname string, err error) {
	defer func() {
		if err != nil {
			log(ctx, "error getting dependency chart name: %v", err)
			return
		}
		log(ctx, "chart name for dependency: %v", cname)
	}()
	if d == nil {
		return "", ErrNilDependency
	}
	var crepo, cref, cpath string
	switch {
	case d.AppMetadata.ChartPath != "":
		crepo, cref, cpath = d.AppMetadata.Repo, d.AppMetadata.Ref, d.AppMetadata.ChartPath
	case d.AppMetadata.ChartRepoPath != "":
		rp := &repoPath{}
		if err := rp.parseFromString(d.AppMetadata.ChartRepoPath); err != nil {
			return "", fmt.Errorf("error parsing ChartRepoPath for repo dependency: %v: %w", d.Repo, err)
		}
		crepo, cref, cpath = rp.repo, rp.ref, rp.path
	default:
		return "", fmt.Errorf("repo dependency '%v': %w", d.Repo, ErrMissingPath)
	}
	return g.getChartName(ctx, crepo, cref, cpath)
}

func (g DataGetter) getRefForRepoDependency(ctx context.Context, d *models.RepoConfigDependency, rd models.RepoRevisionData, defaultBranch string, branchMatch bool) (sha, branch string, err error) {
	defer func() {
		if err != nil {
			log(ctx, "error getting ref for repo dependency: %v", err)
			return
		}
		log(ctx, "calculated ref for repo dependency: %v: %v (%v)", d.Repo, branch, sha)
	}()
	if d == nil || d.Repo == "" {
		return "", "", fmt.Errorf("empty Repo field: %w", ErrEmptyArg)
	}
	log(ctx, "fetching branches for %v", d.Repo)
	branches, err := g.RC.GetBranches(ctx, d.Repo)
	if err != nil {
		return "", "", ErrGetRepoBranches
	}
	bi := make([]match.BranchInfo, len(branches))
	for i := range branches {
		bi[i] = match.BranchInfo{Name: branches[i].Name, SHA: branches[i].SHA}
	}
	defb := rd.BaseBranch
	if d.DefaultBranch != "" {
		defb = d.DefaultBranch
	}
	ri := match.RepoInfo{
		SourceBranch:  rd.SourceBranch,
		BaseBranch:    rd.BaseBranch,
		BranchMatch:   !d.DisableBranchMatch,
		DefaultBranch: defb,
	}
	sha, branch, err = match.GetRefForRepo(ri, bi)
	if err != nil {
		return "", "", ErrGetRefForRepo
	}
	// get override if present, but only override the SHA
	if override, ok := g.RepoRefOverrides[d.Repo]; ok {
		sha = override
	}
	return sha, branch, nil
}

const DefaultFallbackBranch = "master"

// Get fetches and parses acyl.yml from owner/repo and any dependent repositories, calculates refs and returns the parsed data.
func (g DataGetter) Get(ctx context.Context, rd models.RepoRevisionData) (*models.RepoConfig, error) {
	var renameRequires = func(ds []models.RepoConfigDependency, old, new string) {
		for i, d := range ds {
			for j, r := range d.Requires {
				if r == old {
					ds[i].Requires[j] = new
				}
			}
		}
	}
	repomap := map[string]struct{}{}
	transitiveDeps := []models.RepoConfigDependency{}
	// d is current dependency
	// parent is the parent dependency (if applicable)
	// ancestor is the "root" dependency (for recursive transitive dependency trees)
	/*
		triggering repo
			 |
			 |---> repo dependency  (ancestor)
			             |
						 |----> transitive dependency (parent)
						                |
										|----> child transitive dependency (d)
	*/
	var processDep func(d, parent, ancestor *models.RepoConfigDependency) (err error)
	processDep = func(d, parent, ancestor *models.RepoConfigDependency) (err error) {
		switch {
		case d == nil:
			return fmt.Errorf("processDep: %w", ErrNilDependency)
		case parent == nil:
			return fmt.Errorf("processDep: %w", ErrNilParent)
		case ancestor == nil:
			return fmt.Errorf("processDep: %w", ErrNilAncestor)
		}
		defer func() {
			if err != nil {
				log(ctx, "error processing dependency: %v: %v", d.Name, err)
				return
			}
			log(ctx, "processing completed for dependency: %v", d.Name)
		}()
		log(ctx, "processing dependency: %v (parent: %v, ancestor: %v)", d.Name, parent.Name, ancestor.Name)
		select {
		case <-ctx.Done():
			return ErrContextCancelled
		default:
			break
		}
		switch {
		case d.Repo != "" && (d.ChartPath != "" || d.ChartRepoPath != ""):
			return fmt.Errorf("only one of Repo, ChartPath, or ChartRepoPath may be used for dependency %v: %w", d.Name, ErrMultipleDependency)
		case d.ChartPath != "" && d.ChartRepoPath != "":
			return fmt.Errorf("either ChartPath or ChartRepoPath may be used, not both, for dependency %v: %w", d.Name, ErrMultipleDependency)
		case d.Repo != "":
			if _, ok := repomap[d.Repo]; ok {
				return fmt.Errorf("duplicate repository dependency for repo %v: %w", d.Repo, ErrDuplicateDependency)
			}
			repomap[d.Repo] = struct{}{}
			bm := !ancestor.DisableBranchMatch
			defb := DefaultFallbackBranch
			if ancestor.DefaultBranch != "" {
				defb = ancestor.DefaultBranch
			}
			dref, dbranch, err := g.getRefForRepoDependency(ctx, d, rd, defb, bm)
			if err != nil {
				return fmt.Errorf("error getting ref for repo dependency: %v: %w", d.Repo, err)
			}
			drc := models.RepoConfig{}
			if err := g.GetAcylYAML(ctx, &drc, d.Repo, dref); err != nil {
				return fmt.Errorf("error processing %v acyl.yml: %w", d.Repo, err)
			}
			drc.Application.Branch = dbranch
			d.AppMetadata = drc.Application
			if d.Name == "" {
				name, err := g.getDependencyChartName(ctx, d)
				if err != nil {
					return fmt.Errorf("%v: %v: %w", d.Repo, err, ErrGetChartName)
				}
				d.Name = name
			}

			renames := map[string]string{}
			deps := []models.RepoConfigDependency{}
			for i := range drc.Dependencies.Direct {
				dd := &drc.Dependencies.Direct[i]
				if err := processDep(dd, d, ancestor); err != nil {
					return fmt.Errorf("error processing direct dependency of %v: %v: %w", d.Name, dd.Name, err)
				}
				old, new := dd.Name, models.GetName(d.Repo)+"-"+dd.Name
				dd.Name = new
				renames[old] = new
				d.Requires = append(d.Requires, dd.Name)
				dd.Parent = d.Name
				deps = append(deps, *dd)
			}
			for old, new := range renames {
				renameRequires(deps, old, new)
			}
			transitiveDeps = append(transitiveDeps, deps...)

		case d.ChartPath != "" || d.ChartRepoPath != "":
			if d.DisableBranchMatch || d.DefaultBranch != "" {
				return fmt.Errorf("incompatible options for dependency '%v': %w", d.Name, ErrBranchAndRepo)
			}
			var drepo, dref, dbranch string
			if d.ChartPath == "" {
				rp := &repoPath{}
				if err := rp.parseFromString(d.ChartRepoPath); err != nil {
					return fmt.Errorf("dependency error: %v: %w", d.Name, err)
				}
				drepo = rp.repo
				dref = rp.ref
			} else {
				drepo = parent.AppMetadata.Repo
				dref = parent.AppMetadata.Ref
				dbranch = parent.AppMetadata.Branch
			}
			d.AppMetadata = models.RepoConfigAppMetadata{
				Repo:              drepo,
				Ref:               dref,
				Branch:            dbranch,
				ChartPath:         d.ChartPath,
				ChartRepoPath:     d.ChartRepoPath,
				ChartVarsPath:     d.ChartVarsPath,
				ChartVarsRepoPath: d.ChartVarsRepoPath,
			}
			if d.Name == "" {
				name, err := g.getDependencyChartName(ctx, d)
				if err != nil {
					return fmt.Errorf("%v: %w", d.AppMetadata.Repo)
				}
				d.Name = name
			}
		default:
			return fmt.Errorf("dependency error: %v: :%w", d.Name, ErrMultipleDependency)
		}
		d.AppMetadata.SetValueDefaults()
		return nil
	}
	rc := models.RepoConfig{}
	if err := g.GetAcylYAML(ctx, &rc, rd.Repo, rd.SourceSHA); err != nil {
		return nil, fmt.Errorf("error processing target repo acyl.yml: %w", err)
	}
	repomap[rd.Repo] = struct{}{}
	rc.Application.Branch = rd.SourceBranch
	parent := &models.RepoConfigDependency{AppMetadata: rc.Application}
	for i := range rc.Dependencies.Direct {
		d := &rc.Dependencies.Direct[i]
		if err := processDep(d, parent, d); err != nil {
			return nil, fmt.Errorf("error processing direct dependencies: %w", err)
		}
	}
	for _, td := range transitiveDeps {
		rc.Dependencies.Direct = append(rc.Dependencies.Direct, td)
	}

	transitiveDeps = []models.RepoConfigDependency{}
	for i := range rc.Dependencies.Environment {
		d := &rc.Dependencies.Environment[i]
		if err := processDep(d, parent, d); err != nil {
			return nil, fmt.Errorf("error processing environment dependencies: %w", err)
		}
	}
	for _, td := range transitiveDeps {
		rc.Dependencies.Environment = append(rc.Dependencies.Environment, td)
	}

	if ok, err := rc.Dependencies.ValidateNames(); !ok {
		return nil, fmt.Errorf("%v: %w", err, ErrValidateDependencyNames)
	}
	return &rc, nil
}

// repoPath models a path within a repo at a ref
type repoPath struct {
	repo, path, ref string
}

func (rp *repoPath) parseFromString(crp string) error {
	// chart_repo_path: dollarshaveclub/helm-charts@master:path/to/chart
	psl := strings.Split(crp, ":")
	if len(psl) != 2 {
		return fmt.Errorf("exactly one ':' required in repo path '%v': %w", crp, ErrMalformedRepoPath)
	}
	rp.path = psl[1]
	if strings.Contains(psl[0], "@") {
		rsl := strings.Split(psl[0], "@")
		if len(rsl) != 2 {
			return fmt.Errorf("no more than one '@' may be present in repo path '%v': %w", psl[0], ErrMalformedRepoPath)
		}
		rp.ref = rsl[1]
		psl[0] = rsl[0]
	}
	if len(strings.Split(psl[0], "/")) != 2 {
		return fmt.Errorf("exactly one '/' is required in repo path '%v': %w", psl[0], ErrMalformedRepoPath)
	}
	rp.repo = psl[0]
	return nil
}

// chartLocation models the location for a chart and the associated vars file
type chartLocation struct {
	chart repoPath
	vars  repoPath
}

func getChartLocation(d models.RepoConfigDependency) (chartLocation, error) {
	loc := chartLocation{}
	if d.AppMetadata.ChartPath == "" {
		if d.AppMetadata.ChartRepoPath == "" {
			return loc, ErrMissingPath
		}
		rp := &repoPath{}
		err := rp.parseFromString(d.AppMetadata.ChartRepoPath)
		if err != nil {
			return loc, fmt.Errorf("error validating ChartRepoPath: %w", err)
		}
		loc.chart = *rp
	} else {
		loc.chart.repo = d.AppMetadata.Repo
		loc.chart.path = d.AppMetadata.ChartPath
		loc.chart.ref = d.AppMetadata.Ref
	}
	switch {
	case d.AppMetadata.ChartVarsPath != "":
		loc.vars.repo = d.AppMetadata.Repo
		loc.vars.path = d.AppMetadata.ChartVarsPath
		loc.vars.ref = d.AppMetadata.Ref
	case d.AppMetadata.ChartVarsRepoPath != "":
		rp := &repoPath{}
		err := rp.parseFromString(d.AppMetadata.ChartVarsRepoPath)
		if err != nil {
			return loc, fmt.Errorf("error validating ChartVarsRepoPath: %w", err)
		}
		loc.vars = *rp
	}
	return loc, nil
}

// ChartLocation models the local filesystem path for the chart and the associated vars file
type ChartLocation struct {
	ChartPath, VarFilePath string
	ValueOverrides         map[string]string
}

// ChartLocations is a map of dependency name to ChartLocation
type ChartLocations map[string]ChartLocation

// FetchCharts fetches the charts for the repo and all dependencies, writing them to the filesystem g.FS at basePath/[offset]/[name] and returns a map of dependency name to filesystem path
func (g DataGetter) FetchCharts(ctx context.Context, rc *models.RepoConfig, basePath string) (ChartLocations, error) {
	// returns the local filesystem path of the chart and vars file (in order)
	fetchChartAndVars := func(i int, d models.RepoConfigDependency) (_ *ChartLocation, err error) {
		defer func() {
			if err != nil {
				log(ctx, "error fetching chart and vars for dependency: %v: %v", d.Name, err)
				return
			}
			log(ctx, "success fetching chart and vars for dependency: %v", d.Name)
		}()
		log(ctx, "fetching chart and vars for dependency: %v", d.Name)
		out := &ChartLocation{ValueOverrides: make(map[string]string)}
		cloc, err := getChartLocation(d)
		if err != nil {
			return nil, fmt.Errorf("error getting chart location: %w", err)
		}
		cd := path.Join(basePath, strconv.Itoa(i), d.Name)
		log(ctx, "getting directory contents: %v@%v: %v", cloc.chart.repo, cloc.chart.ref, cloc.chart.path)
		dc, err := g.RC.GetDirectoryContents(ctx, cloc.chart.repo, cloc.chart.path, cloc.chart.ref)
		if err != nil {
			return nil, fmt.Errorf("error fetching chart contents: %w", ErrGetDirectoryContents)
		}
		for n, c := range dc {
			n = strings.Replace(n, filepath.Clean(cloc.chart.path), "", -1) // remove chart path
			fp := path.Join(cd, n)
			if err = g.FS.MkdirAll(path.Dir(fp), os.ModePerm); err != nil {
				return nil, ErrCreatingDirectory
			}
			if c.Symlink {
				if err := g.FS.Symlink(c.SymlinkTarget, fp); err != nil {
					return nil, fmt.Errorf("%v: %w", err, ErrCreatingSymlink)
				}
				continue
			}
			f, err := g.FS.Create(fp)
			if err != nil {
				return nil, fmt.Errorf("%v: %w", err, ErrCreatingFile)
			}
			defer f.Close()
			var n int
			for {
				i, err := f.Write(c.Contents[n:len(c.Contents)])
				if err != nil {
					return nil, fmt.Errorf("%v: %w", err, ErrWritingFile)
				}
				n += i
				if n == len(c.Contents) {
					break
				}
			}
		}
		out.ChartPath = cd
		if cloc.vars.repo != "" {
			log(ctx, "getting file contents: %v@%v: %v", cloc.vars.repo, cloc.vars.ref, cloc.vars.path)
			fc, err := g.RC.GetFileContents(ctx, cloc.vars.repo, cloc.vars.path, cloc.vars.ref)
			if err != nil {
				return nil, fmt.Errorf("%v: %w", err, ErrGetFileContents)
			}
			vcd := path.Join(cd, "vars.yml")
			vf, err := g.FS.Create(vcd)
			if err != nil {
				return nil, fmt.Errorf("%v: %w", err, ErrCreatingFile)
			}
			defer vf.Close()
			n, err := vf.Write(fc)
			if err != nil {
				return nil, fmt.Errorf("%v: %w", err, ErrWritingFile)
			}
			if n < len(fc) {
				return nil, ErrShortWrite
			}
			for _, v := range d.AppMetadata.ValueOverrides {
				vsl := strings.SplitN(v, "=", 2)
				if len(vsl) != 2 {
					return nil, fmt.Errorf("malformed value override '%v': %w", v, ErrMalformedValueOverride)
				}
				out.ValueOverrides[vsl[0]] = vsl[1]
			}
			out.VarFilePath = vcd
		}
		return out, nil
	}
	name := models.GetName(rc.Application.Repo)
	loc, err := fetchChartAndVars(0, models.RepoConfigDependency{Name: name, AppMetadata: rc.Application})
	if err != nil {
		return nil, fmt.Errorf("error getting primary repo chart: %w", err)
	}
	if loc == nil {
		return nil, ErrNilLocation
	}
	out := map[string]ChartLocation{name: *loc}
	ctx, cf := context.WithTimeout(ctx, 2*time.Minute)
	defer cf()
	eg, _ := errgroup.WithContext(ctx)
	couts := make([]ChartLocation, rc.Dependencies.Count())
	offsetmap := make(map[int]*models.RepoConfigDependency, rc.Dependencies.Count())
	for i, d := range rc.Dependencies.All() {
		d := d
		i := i
		offsetmap[i] = &d
		eg.Go(func() error {
			loc, err = fetchChartAndVars(i+1, d)
			if err != nil {
				return fmt.Errorf("error getting dependency chart: %v: %w", d.Name, err)
			}
			if loc == nil {
				return ErrNilLocation
			}
			couts[i] = *loc
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("error fetching charts: %w", err)
	}
	for i := 0; i < rc.Dependencies.Count(); i++ {
		loc := couts[i]
		d := offsetmap[i]
		for _, v := range d.ValueOverrides { // Dependency value_overrides override anything in the application metadata
			vsl := strings.SplitN(v, "=", 2)
			if len(vsl) != 2 {
				return nil, fmt.Errorf("malformed value override '%v': %w", v, ErrMalformedValueOverride)

			}
			loc.ValueOverrides[vsl[0]] = vsl[1]
		}
		out[d.Name] = loc
	}
	return out, nil
}
