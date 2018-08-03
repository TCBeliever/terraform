package discovery

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	getter "github.com/hashicorp/go-getter"
	multierror "github.com/hashicorp/go-multierror"

	"github.com/hashicorp/terraform/httpclient"
	"github.com/hashicorp/terraform/registry"
	"github.com/hashicorp/terraform/registry/regsrc"
	"github.com/hashicorp/terraform/registry/response"
	"github.com/hashicorp/terraform/svchost/disco"
	"github.com/mitchellh/cli"
)

// Releases are located by querying the terraform registry.

const protocolVersionHeader = "x-terraform-protocol-version"

var httpClient *http.Client

var errVersionNotFound = errors.New("version not found")

func init() {
	httpClient = httpclient.New()

	httpGetter := &getter.HttpGetter{
		Client: httpClient,
		Netrc:  true,
	}

	getter.Getters["http"] = httpGetter
	getter.Getters["https"] = httpGetter
}

// An Installer maintains a local cache of plugins by downloading plugins
// from an online repository.
type Installer interface {
	Get(name string, req Constraints) (PluginMeta, error)
	PurgeUnused(used map[string]PluginMeta) (removed PluginMetaSet, err error)
}

// ProviderInstaller is an Installer implementation that knows how to
// download Terraform providers from the official HashiCorp releases service
// into a local directory. The files downloaded are compliant with the
// naming scheme expected by FindPlugins, so the target directory of a
// provider installer can be used as one of several plugin discovery sources.
type ProviderInstaller struct {
	Dir string

	// Cache is used to access and update a local cache of plugins if non-nil.
	// Can be nil to disable caching.
	Cache PluginCache

	PluginProtocolVersion uint

	// OS and Arch specify the OS and architecture that should be used when
	// installing plugins. These use the same labels as the runtime.GOOS and
	// runtime.GOARCH variables respectively, and indeed the values of these
	// are used as defaults if either of these is the empty string.
	OS   string
	Arch string

	// Skip checksum and signature verification
	SkipVerify bool

	Ui cli.Ui // Ui for output

	// Services is a required *disco.Disco, which may have services and
	// credentials pre-loaded.
	Services *disco.Disco

	// registry client
	registry *registry.Client

	// provider is the name of the provider being installed by this particular
	// instance of ProviderInstaller
	provider string
}

// Get is part of an implementation of type Installer, and attempts to download
// and install a Terraform provider matching the given constraints.
//
// This method may return one of a number of sentinel errors from this
// package to indicate issues that are likely to be resolvable via user action:
//
//     ErrorNoSuchProvider: no provider with the given name exists in the repository.
//     ErrorNoSuitableVersion: the provider exists but no available version matches constraints.
//     ErrorNoVersionCompatible: a plugin was found within the constraints but it is
//                               incompatible with the current Terraform version.
//
// These errors should be recognized and handled as special cases by the caller
// to present a suitable user-oriented error message.
//
// All other errors indicate an internal problem that is likely _not_ solvable
// through user action, or at least not within Terraform's scope. Error messages
// are produced under the assumption that if presented to the user they will
// be presented alongside context about what is being installed, and thus the
// error messages do not redundantly include such information.
func (i *ProviderInstaller) Get(provider string, req Constraints) (PluginMeta, error) {
	// a little bit of initialization
	// I don't think this goes here. Suggestions?
	if i.OS == "" {
		i.OS = runtime.GOOS
	}
	if i.Arch == "" {
		i.Arch = runtime.GOARCH
	}
	if i.registry == nil {
		i.registry = registry.NewClient(i.Services, nil, nil)
	}
	i.setProvider(provider)

	allVersions, err := i.listProviderVersions(provider)

	// TODO: return multiple errors
	if err != nil {
		return PluginMeta{}, ErrorNoSuchProvider
	}
	if len(allVersions.Versions) == 0 {
		return PluginMeta{}, ErrorNoSuitableVersion
	}

	// Filter the list of plugin versions to those which meet the version constraints
	versions := allowedVersions(allVersions, req)
	if len(versions) == 0 {
		return PluginMeta{}, ErrorNoSuitableVersion
	}

	// sort them newest to oldest
	response.Collection(versions).Sort()

	// the winning version is the newest
	versionMeta := versions[0]
	if len(versionMeta.Protocols) == 0 {
		return PluginMeta{}, fmt.Errorf("no provider protocols listed")
	}
	if len(versionMeta.Platforms) == 0 {
		return PluginMeta{}, fmt.Errorf("no provider platforms listed")
	}

	// get a Version from the version string
	// we already know this will not error from the preceding functions
	v, _ := VersionStr(versionMeta.Version).Parse()

	// Ensure that our installation directory exists
	err = os.MkdirAll(i.Dir, os.ModePerm)
	if err != nil {
		return PluginMeta{}, fmt.Errorf("failed to create plugin dir %s: %s", i.Dir, err)
	}

	// check plugin protocol compatibility
	// We only validate the most recent version that meets the version constraints.
	// see RFC TF-055: Provider Protocol Versioning for more information
	err = i.checkPluginProtocol(versionMeta)
	if err != nil {
		return PluginMeta{}, err
	}

	var downloadURLs *response.TerraformProviderPlatformLocation
	// check plugin platform compatibility
	for _, p := range versionMeta.Platforms {
		if p.Arch == i.Arch && p.OS == i.OS {
			downloadURLs, err = i.listProviderDownloadURLs(provider, versionMeta.Version)
			if err != nil {
				return PluginMeta{}, err
			}
			break
		}
		// TODO: return the most recent compatible versions
		// return PluginMeta{}, ErrorNoVersionCompatibleWithPlatform
		return PluginMeta{}, fmt.Errorf("The latest version of plugin %q does not support the requested platform %s %s", provider, i.OS, i.Arch)
	}

	providerURL := downloadURLs.DownloadURL

	if !i.SkipVerify {
		sha256, err := i.getProviderChecksum(downloadURLs)
		if err != nil {
			return PluginMeta{}, err
		}

		// add the checksum parameter for go-getter to verify the download for us.
		if sha256 != "" {
			providerURL = providerURL + "?checksum=sha256:" + sha256
		}
	}

	i.Ui.Info(fmt.Sprintf("- Downloading plugin for provider %q (%s)...", provider, versionMeta.Version))
	log.Printf("[DEBUG] getting provider %q version %q", provider, versionMeta.Version)
	err = i.install(provider, v, providerURL)
	if err != nil {
		return PluginMeta{}, err
	}

	// Find what we just installed
	// (This is weird, because go-getter doesn't directly return
	//  information about what was extracted, and we just extracted
	//  the archive directly into a shared dir here.)
	log.Printf("[DEBUG] looking for the %s %s plugin we just installed", provider, versionMeta.Version)
	metas := FindPlugins("provider", []string{i.Dir})
	log.Printf("[DEBUG] all plugins found %#v", metas)
	metas, _ = metas.ValidateVersions()
	metas = metas.WithName(provider).WithVersion(v)
	log.Printf("[DEBUG] filtered plugins %#v", metas)
	if metas.Count() == 0 {
		// This should never happen. Suggests that the release archive
		// contains an executable file whose name doesn't match the
		// expected convention.
		return PluginMeta{}, fmt.Errorf(
			"failed to find installed plugin version %s; this is a bug in Terraform and should be reported",
			versionMeta.Version,
		)
	}

	if metas.Count() > 1 {
		// This should also never happen, and suggests that a
		// particular version was re-released with a different
		// executable filename. We consider releases as immutable, so
		// this is an error.
		return PluginMeta{}, fmt.Errorf(
			"multiple plugins installed for version %s; this is a bug in Terraform and should be reported",
			versionMeta.Version,
		)
	}

	// By now we know we have exactly one meta, and so "Newest" will
	// return that one.
	return metas.Newest(), nil

}

func (i *ProviderInstaller) install(provider string, version Version, url string) error {
	if i.Cache != nil {
		log.Printf("[DEBUG] looking for provider %s %s in plugin cache", provider, version)
		cached := i.Cache.CachedPluginPath("provider", provider, version)
		if cached == "" {
			log.Printf("[DEBUG] %s %s not yet in cache, so downloading %s", provider, version, url)
			err := getter.Get(i.Cache.InstallDir(), url)
			if err != nil {
				return err
			}
			// should now be in cache
			cached = i.Cache.CachedPluginPath("provider", provider, version)
			if cached == "" {
				// should never happen if the getter is behaving properly
				// and the plugins are packaged properly.
				return fmt.Errorf("failed to find downloaded plugin in cache %s", i.Cache.InstallDir())
			}
		}

		// Link or copy the cached binary into our install dir so the
		// normal resolution machinery can find                                                     it.
		filename := filepath.Base(cached)
		targetPath := filepath.Join(i.Dir, filename)

		log.Printf("[DEBUG] installing %s %s to %s from local cache %s", provider, version, targetPath, cached)

		// Delete if we can. If there's nothing there already then no harm done.
		// This is important because we can't create a link if there's
		// already a file of the same name present.
		// (any other error here we'll catch below when we try to write here)
		os.Remove(targetPath)

		// We don't attempt linking on Windows because links are not
		// comprehensively supported by all tools/apps in Windows and
		// so we choose to be conservative to avoid creating any
		// weird issues for Windows users.
		linkErr := errors.New("link not supported for Windows") // placeholder error, never actually returned
		if runtime.GOOS != "windows" {
			// Try hard linking first. Hard links are preferable because this
			// creates a self-contained directory that doesn't depend on the
			// cache after install.
			linkErr = os.Link(cached, targetPath)

			// If that failed, try a symlink. This _does_ depend on the cache
			// after install, so the user must manage the cache more carefully
			// in this case, but avoids creating redundant copies of the
			// plugins on disk.
			if linkErr != nil {
				linkErr = os.Symlink(cached, targetPath)
			}
		}

		// If we still have an error then we'll try a copy as a fallback.
		// In this case either the OS is Windows or the target filesystem
		// can't support symlinks.
		if linkErr != nil {
			srcFile, err := os.Open(cached)
			if err != nil {
				return fmt.Errorf("failed to open cached plugin %s: %s", cached, err)
			}
			defer srcFile.Close()

			destFile, err := os.OpenFile(targetPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s: %s", targetPath, err)
			}

			_, err = io.Copy(destFile, srcFile)
			if err != nil {
				destFile.Close()
				return fmt.Errorf("failed to copy cached plugin from %s to %s: %s", cached, targetPath, err)
			}

			err = destFile.Close()
			if err != nil {
				return fmt.Errorf("error creating %s: %s", targetPath, err)
			}
		}

		// One way or another, by the time we get here we should have either
		// a link or a copy of the cached plugin within i.Dir, as expected.
	} else {
		log.Printf("[DEBUG] plugin cache is disabled, so downloading %s %s from %s", provider, version, url)
		err := getter.Get(i.Dir, url)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *ProviderInstaller) PurgeUnused(used map[string]PluginMeta) (PluginMetaSet, error) {
	purge := make(PluginMetaSet)

	present := FindPlugins("provider", []string{i.Dir})
	for meta := range present {
		chosen, ok := used[meta.Name]
		if !ok {
			purge.Add(meta)
		}
		if chosen.Path != meta.Path {
			purge.Add(meta)
		}
	}

	removed := make(PluginMetaSet)
	var errs error
	for meta := range purge {
		path := meta.Path
		err := os.Remove(path)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf(
				"failed to remove unused provider plugin %s: %s",
				path, err,
			))
		} else {
			removed.Add(meta)
		}
	}

	return removed, errs
}

func (i *ProviderInstaller) getProviderChecksum(urls *response.TerraformProviderPlatformLocation) (string, error) {
	checksums, err := getPluginSHA256SUMs(urls.ShasumsURL, urls.ShasumsSignatureURL)
	if err != nil {
		return "", err
	}

	return checksumForFile(checksums, urls.Filename), nil
}

// list all versions available for the named provider
func (i *ProviderInstaller) listProviderVersions(name string) (*response.TerraformProviderVersions, error) {
	provider := regsrc.NewTerraformProvider(name, i.OS, i.Arch)
	versions, err := i.registry.TerraformProviderVersions(provider)
	return versions, err
}

func (i *ProviderInstaller) listProviderDownloadURLs(name, version string) (*response.TerraformProviderPlatformLocation, error) {
	urls, err := i.registry.TerraformProviderLocation(regsrc.NewTerraformProvider(name, i.OS, i.Arch), version)
	if urls == nil {
		return nil, fmt.Errorf("No download urls found for provider %s", i.provider)
	}
	return urls, err
}

func (i *ProviderInstaller) checkPluginProtocol(versionMeta *response.TerraformProviderVersion) error {
	// TODO: should this be a different error? We should probably differentiate between
	// no compatible versions and no protocol versions listed at all
	// No protocols at all!
	if len(versionMeta.Protocols) == 0 {
		return ErrorNoVersionCompatible
	}

	protoString := strconv.Itoa(int(i.PluginProtocolVersion))
	protocolVersion, err := VersionStr(protoString).Parse()
	if err != nil {
		return fmt.Errorf("invalid plugin protocol version: %q", i.PluginProtocolVersion)
	}
	protocolConstraint, err := protocolVersion.MinorUpgradeConstraintStr().Parse()
	if err != nil {
		// This should not fail if the preceding function succeeded.
		return fmt.Errorf("invalid plugin protocol version: %q", protocolVersion.String())
	}

	for _, p := range versionMeta.Protocols {
		proPro, err := VersionStr(p).Parse()
		if err != nil {
			// invalid protocol reported by the registry. Move along.
			log.Printf("[WARN] invalid provider protocol version %q found in the registry", versionMeta.Version)
			continue
		}
		// success!
		if protocolConstraint.Allows(proPro) {
			return nil
		}
	}
	// TODO: get most recent compatible plugin and return a handy-dandy string for the user
	// latest, err := getNewestCompatiblePlugin
	// i.Ui.output|info): "the latest version of plugin BLAH which supports protocol BLAH is BLAH"
	// Add this to your provider block:
	// version = ~BLAH
	// and if none is found, return ErrorNoVersionCompatible
	return ErrorNoVersionCompatible
}

func (i *ProviderInstaller) setProvider(p string) {
	if i.provider == "" {
		i.provider = p
	}
}

// take the list of available versions for a plugin, and filter out those that
// don't fit the constraints.
func allowedVersions(available *response.TerraformProviderVersions, required Constraints) []*response.TerraformProviderVersion {
	var allowed []*response.TerraformProviderVersion

	for _, v := range available.Versions {
		version, err := VersionStr(v.Version).Parse()
		if err != nil {
			log.Printf("[WARN] invalid version found for %q: %s", available.ID, err)
			continue
		}
		if required.Allows(version) {
			allowed = append(allowed, v)
		}
	}
	return allowed
}

func checksumForFile(sums []byte, name string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 && parts[1] == name {
			return parts[0]
		}
	}
	return ""
}

// fetch the SHA256SUMS file provided, and verify its signature.
func getPluginSHA256SUMs(sumsURL, sigURL string) ([]byte, error) {
	sums, err := getFile(sumsURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching checksums: %s", err)
	}

	sig, err := getFile(sigURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching checksums signature: %s", err)
	}

	if err := verifySig(sums, sig); err != nil {
		return nil, err
	}

	return sums, nil
}

func getFile(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}
	return data, nil
}
