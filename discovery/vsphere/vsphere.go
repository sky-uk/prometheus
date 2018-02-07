package vsphere

import (
	"fmt"
	"net/url"
	"time"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/kit/log/level"
	"github.com/go-kit/kit/log"
	"github.com/vmware/govmomi/vim25/debug"
	"github.com/vmware/govmomi"
	"github.com/vmware/vic/pkg/vsphere/tags"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/prometheus/prometheus/util/strutil"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/common/model"
	yaml_util "github.com/prometheus/prometheus/util/yaml"
	"github.com/davecgh/go-spew/spew"
)

//TODO Remove hardcoded value
const (
	defaultAPITimeout = time.Minute * 5
	vSphereLabel = model.MetaLabelPrefix + "vsphere_"
	)

type VSphereClient struct {
	// The VIM/govmomi client.
	vimClient *govmomi.Client

	// The specialized tags client SDK imported from vmware/vic.
	tagsClient *tags.RestClient
}

type Discovery struct {
	VSphereServer string
	logger   log.Logger
	interval   time.Duration
	Password      string
	User	string
	InsecureFlag  bool
	Debug         bool
	DebugPath     string
	DebugPathRun  string
}

type SDConfig struct {
	VSphereServer	string	`yaml:"vsphereserver"`
	Password      string	`yaml:"password"`
	User	string			`yaml:"auth_user"`
	InsecureFlag  bool			`yaml:"allow_insecure_ssl"`
	Debug         bool			`yaml:"debug,omitempty"`
	DebugPath     string		`yaml:"debug_outpath,omitempty"`
	DebugPathRun  string	`yaml:"debug_runpath,omitempty"`
	XXX map[string]interface{} `yaml:",inline"`
}

var (

	// DefaultSDConfig is the default DNS SD configuration.
	DefaultSDConfig = SDConfig{
		InsecureFlag: true,
	}
)

func NewDiscovery(conf *SDConfig, logger log.Logger) *Discovery {
	return &Discovery{
		VSphereServer: conf.VSphereServer,
		User: conf.User,
		Password: conf.Password,
		InsecureFlag: conf.InsecureFlag,
		//TODO remove hardcoded value
		interval: 30 * time.Second,
		logger: logger,
	}

}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SDConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultSDConfig
	type plain SDConfig
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	if err := yaml_util.CheckOverflow(c.XXX, "vsphere_sd_config"); err != nil {
		return err
	}
	if c.VSphereServer == "" {
		return fmt.Errorf("vsphere-sd: VSphereServer is required")
	}
	if c.Password == "" {
		return fmt.Errorf("vsphere-sd password is required")
	}
	if c.User == "" {
		return fmt.Errorf("vsphere-sd user is required")

	}
	return nil
}

func (d *Discovery) EnableDebug() error {
	if !d.Debug {
		return nil
	}

	// Base path for storing debug logs.
	r := d.DebugPath
	if r == "" {
		r = filepath.Join(os.Getenv("HOME"), ".govmomi")
	}
	r = filepath.Join(r, "debug")

	// Path for this particular run.
	run := d.DebugPathRun
	if run == "" {
		now := time.Now().Format("2006-01-02T15-04-05.999999999")
		r = filepath.Join(r, now)
	} else {
		// reuse the same path
		r = filepath.Join(r, run)
		_ = os.RemoveAll(r)
	}

	err := os.MkdirAll(r, 0700)
	if err != nil {
		//log.Printf("[ERROR] Client debug setup failed: %v", err)
		level.Error(d.logger).Log("msg", "govmomi debug setup failed", "err", err)
		return err
	}

	p := debug.FileProvider{
		Path: r,
	}

	debug.SetProvider(&p)
	return nil
}

// Client returns a new client for accessing VMWare vSphere Tags.
func (d *Discovery) Client() (*VSphereClient, error) {

	client := new(VSphereClient)

	u, err := url.Parse("https://" + d.VSphereServer + "/sdk")
	if err != nil {
		return nil, fmt.Errorf("Error parse url: %s", err)
	}

	u.User = url.UserPassword(d.User, d.Password)

	err = d.EnableDebug()
	if err != nil {
		return nil, fmt.Errorf("Error setting up client debug: %s", err)
	}

	// Set up the VIM/govmomi client connection.
	vctx, vcancel := context.WithTimeout(context.Background(), defaultAPITimeout)
	defer vcancel()
	client.vimClient, err = govmomi.NewClient(vctx, u, d.InsecureFlag)
	if err != nil {
		return nil, fmt.Errorf("Error setting up client: %s", err)
	}

	level.Info(d.logger).Log("msg", "VMWare vSphere Client configured for URL", "info",d.VSphereServer)

	// Skip the rest of this function if we are not setting up the tags client. This is if
	//TODO Validate endpoint version
	//	if !isEligibleTagEndpoint(client.vimClient) {
	//		log.Printf("[WARN] Connected endpoint does not support tags (%s)", viapi.ParseVersionFromClient(client.vimClient))
	//		return client, nil
	//	}

	// Otherwise, connect to the CIS REST API for tagging.
	level.Info(d.logger).Log("msg", "Logging in toCIS REST login", "info",d.VSphereServer )
	client.tagsClient = tags.NewClient(u, d.InsecureFlag, "")
	tctx, tcancel := context.WithTimeout(context.Background(), defaultAPITimeout)
	defer tcancel()
	if err := client.tagsClient.Login(tctx); err != nil {
		return nil, fmt.Errorf("Error connecting to CIS REST endpoint: %s", err)
	}
	// Done
	//log.Println("[INFO] CIS REST login successful")
	level.Info(d.logger).Log("msg", "CIS REST login successful", "info")

	return client, nil
}

// Client returns a new client for accessing VMWare vSphere.
func (d *Discovery) vmClient() (*govmomi.Client, error) {


	u, err := url.Parse("https://" + d.VSphereServer + "/sdk")
	if err != nil {
		return nil, fmt.Errorf("Error parse url: %s", err)
	}

	u.User = url.UserPassword(d.User, d.Password)

	err = d.EnableDebug()
	if err != nil {
		return nil, fmt.Errorf("Error setting up client debug: %s", err)
	}

	// Set up the VIM/govmomi client connection.
	vctx, vcancel := context.WithTimeout(context.Background(), defaultAPITimeout)
	defer vcancel()
	client, err := govmomi.NewClient(vctx, u, d.InsecureFlag)
	if err != nil {
		return nil, fmt.Errorf("Error setting up VM client: %s", err)
	}

	return client, nil
}

func (c *VSphereClient) TagsClient() (*tags.RestClient, error) {
	if c.tagsClient == nil {
		//TODO use real tags version
		return nil, fmt.Errorf("tags require %s or higher", "tagsMinVersion")
	}
	return c.tagsClient, nil
}

func (d *Discovery) getVMlist() ([]mo.VirtualMachine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultAPITimeout)
	defer cancel()

	vmclient, err := d.vmClient()
	if err != nil {
		return nil, err
	}
	m := view.NewManager(vmclient.Client)
	v, err := m.CreateContainerView(ctx, vmclient.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return nil, err
	}
	var vms []mo.VirtualMachine
	err = v.Retrieve(ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		return nil, err
	}
	return vms, nil
}

func (d *Discovery) refresh() (tg *targetgroup.Group, err error) {
	//get a list of VMs in vsphere
	vms, err := d.getVMlist()
	if err != nil {
		return nil, err
	}

	//Setup govmomi CIS client to get tags
	c, err := d.Client()
	if err != nil {
		return nil, err
	}
	tagsclient, err := c.TagsClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultAPITimeout)
	defer cancel()

	tg = &targetgroup.Group{
		Source: d.VSphereServer,
	}


	for _, vm := range vms {
		address := vm.Summary.Guest.IpAddress
		if len(address) < 1 {
			level.Warn(d.logger).Log("msg", "No address for VM", "node", vm.Summary.Config.Name)
			continue
		}

		tagIDs, err := tagsclient.ListAttachedTags(ctx, vm.ManagedEntity.Reference().Value,"VirtualMachine" )
		if err != nil {
			level.Error(d.logger).Log("msg", "Failed to get attached tags", "err", err, "node", vm.Summary.Config.Name)
			continue
		}

		labels := model.LabelSet{
			vSphereLabel + "hostname": model.LabelValue(vm.Summary.Config.Name),
			model.LabelName(model.AddressLabel): model.LabelValue(address),
		}

		for _, item := range tagIDs {
			vmtag, err := tagsclient.GetTag(ctx, item)
			if err != nil {
				level.Error(d.logger).Log("msg", "Failed to get vm tag", "err", err, "node", vm.Summary.Config.Name)
				continue
			}
			tagName := strutil.SanitizeLabelName(vmtag.Name)
			if strings.HasPrefix(tagName, "__meta_") {
				labels[model.LabelName(tagName)] = model.LabelValue(vmtag.Description)

			}

		}

		tg.Targets = append(tg.Targets, labels)
	}

	return tg, nil
}

// Run implements the Discoverer interface.
func (d *Discovery) Run(ctx context.Context, ch chan<- []*targetgroup.Group) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	// Get an initial set right away.
	tg, err := d.refresh()
	if err != nil {
		level.Error(d.logger).Log("msg", "Refresh failed", "err", err)
	} else {
		select {
		case ch <- []*targetgroup.Group{tg}:
		case <-ctx.Done():
			return
		}
	}

	for {
		select {
		case <-ticker.C:
			tg, err := d.refresh()
			if err != nil {
				level.Error(d.logger).Log("msg", "Refresh failed", "err", err)
				continue
			}

			select {
			case ch <- []*targetgroup.Group{tg}:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
