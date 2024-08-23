package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	cv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/traffic"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/classifier"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/debug"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/k8s_watcher"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node_watcher"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	dblib "github.com/dinoallo/sealos-networkmanager-agent/pkg/db"
	"github.com/dinoallo/sealos-networkmanager-agent/pkg/db/mongo"
	loglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	zaplog "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
	netlib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/net"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	mainNetlib              netlib.NetLib = netlib.NewNMNetLib()
	mainDB                  dblib.DB
	mainClassifier          modules.Classifier
	mainTrafficStore        modules.TrafficStore
	mainTrafficFactory      modules.BPFTrafficFactory
	mainPortExposureChecker modules.PortExposureChecker

	mainLogger   loglib.Logger
	mainMgr      ctrl.Manager
	globalConfig *conf.GlobalConfig

	ErrInitingGlobalConfig    = errors.New("failed to init the global config")
	ErrStartingDB             = errors.New("failed to start the database")
	ErrStartingTrafficFactory = errors.New("failed to start the traffic factory")
	ErrStartingCCMWatcher     = errors.New("failed to start the cilium ccm watcher")
	ErrStartingClassifier     = errors.New("failed to start the classifier")
	ErrStartingTrafficStore   = errors.New("failed to start the traffic store")
	ErrStartingCtrlManager    = errors.New("failed to start the ctrl manager")
	ErrCreatingCtrlManager    = errors.New("failed to create the ctrl manager")
	ErrStartingHostDevWatcher = errors.New("failed to start the host device watcher")
	ErrStartingNetnsWatcher   = errors.New("failed to start the net ns watcher")
	ErrStartingPodWatcher     = errors.New("failed to start the pod watcher")
	ErrStartingEpWatcher      = errors.New("failed to start the ep watcher")
	ErrStartingCepWatcher     = errors.New("failed to start the cep watcher")
	ErrStartingIngressWatcher = errors.New("failed to start the ingress watcher")

	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cv2.AddToScheme(scheme))
}

func main() {
	mainCtx := ctrl.SetupSignalHandler()
	err := preCheck()
	if err != nil {
		fmt.Fprintf(os.Stderr, "prechecking failed: %v", err)
		os.Exit(1)
	}
	// init the main logger
	logger, err := zaplog.NewZap(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create the logger: %v\n", err)
		os.Exit(1)
	}
	mainLogger = logger
	// init the global configuration
	_config, err := conf.InitGlobalConfig()
	if err != nil || _config == nil {
		printErr(errors.Join(err, ErrInitingGlobalConfig))
		return
	}
	globalConfig = _config
	logger.Debugf("print global config: %+v", globalConfig)
	// start the database
	if err := startDB(); err != nil {
		printErr(err)
		return
	}
	// start the traffic store
	if err := startTrafficStore(mainCtx); err != nil {
		printErr(err)
		return
	}
	// start the classifier
	if err := startClassifier(); err != nil {
		printErr(err)
		return
	}
	// start the traffic factory
	if err := rlimit.RemoveMemlock(); err != nil {
		printErr(err)
		return
	}
	err, closeTF := startTrafficFactory(mainCtx)
	if err != nil {
		printErr(err)
		return
	}
	if closeTF != nil {
		defer closeTF()
	}
	// start the host device watcher
	err, closeHostDevWatcher := startHostDevWatcher(mainCtx)
	if err != nil {
		printErr(err)
		return
	}
	if closeHostDevWatcher != nil {
		defer closeHostDevWatcher()
	}
	// start the net ns watcher
	err, closeNetnsWatcher := startNetnsWatcher(mainCtx)
	if err != nil {
		printErr(err)
		return
	}
	if closeNetnsWatcher != nil {
		defer closeNetnsWatcher()
	}
	// init the main ctrl manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		printErr(errors.Join(err, ErrCreatingCtrlManager))
		return
	}
	mainMgr = mgr
	// start the port exposure checker
	if err := startPortExposureChecker(); err != nil {
		printErr(err)
		return
	}
	// start the pod watcher
	if err := startPodWatcher(); err != nil {
		printErr(err)
		return
	}
	// start the endpoint watcher
	if err := startEpWatcher(); err != nil {
		printErr(err)
		return
	}
	// start the ingress watcher
	if err := startIngressWatcher(); err != nil {
		printErr(err)
		return
	}
	if err := startDebugService(); err != nil {
		printErr(err)
		return
	}
	// start the ctrl manager
	if err := mainMgr.Start(mainCtx); err != nil {
		printErr(errors.Join(err, ErrStartingCtrlManager))
		return
	}
}

func preCheck() error {
	err := features.HaveMapType(ebpf.RingBuf)
	if err == nil {
		return nil
	} else if err == ebpf.ErrNotSupported {
		return fmt.Errorf("the kernel doesn't support bpf ringbuf so the agent cannot start: %v. maybe try upgrading kernel to at least 5.8", err)
	} else {
		return fmt.Errorf("failed to probe for ringbuf feature: %v", err)
	}
}

func startDB() error {
	config := globalConfig.DBConfig
	if config.Enabled {
		mongoOpts := mongo.NewMongoOpts()
		mongodb, err := mongo.NewMongo(config.Uri, config.Name, mongoOpts)
		if err != nil {
			return errors.Join(err, ErrStartingDB)
		}
		mainDB = mongodb
		return nil
	} else {
		mockingDB := mock.NewTestingDB()
		mainDB = mockingDB
		return nil
	}
}

func startTrafficFactory(ctx context.Context) (error, func()) {
	p := traffic.TrafficFactoryParams{
		Host:                    globalConfig.Host,
		ParentLogger:            mainLogger,
		BPFTrafficFactoryConfig: globalConfig.BPFTrafficFactoryConfig,
		TrafficStore:            mainTrafficStore,
		Classifier:              mainClassifier,
	}
	tf, err := traffic.NewTrafficFactory(p)
	if err != nil {
		return errors.Join(err, ErrStartingTrafficFactory), nil
	}
	tf.Start(ctx)
	closeTF := func() {
		tf.Close()
	}
	mainTrafficFactory = tf
	return nil, closeTF
}

func startClassifier() error {
	config := globalConfig.ClassifierConfig
	if config.Enabled {
		p := classifier.RawTrafficClassifierParams{
			ClassifierConfig: globalConfig.ClassifierConfig,
		}
		c, err := classifier.NewRawTrafficClassifer(p)
		if err != nil {
			return errors.Join(err, ErrStartingClassifier)
		}
		mainClassifier = c
	} else {
		mockConfig := globalConfig.MockConfig
		cfg := mock.DummyClassifierConfig{
			PodAddr:     mockConfig.TrackedPodIP,
			HostAddr:    mockConfig.TrackedHostIP,
			WorldAddr:   mockConfig.TrackedWorldIP,
			SkippedAddr: mockConfig.TrackedSkippedIP,
			PodPort:     mockConfig.TrackedExposedPort,
		}
		c := mock.NewDummyClassifier(cfg)
		mainClassifier = c
	}
	return nil
}

func startTrafficStore(ctx context.Context) error {
	config := globalConfig.TrafficStoreConfig
	if config.Enabled {
		params := store.TrafficStoreParams{
			ParentLogger:       mainLogger,
			DB:                 mainDB,
			TrafficStoreConfig: config,
		}
		s, err := store.NewTrafficStore(params)
		if err != nil {
			return errors.Join(err, ErrStartingTrafficStore)
		}
		mainTrafficStore = s
		if err := s.Start(ctx); err != nil {
			return errors.Join(err, ErrStartingTrafficStore)
		}
	} else {
		mockConfig := globalConfig.MockConfig
		s := &mock.DummyTrafficStore{
			MarkedPodAddrForPodTraffic:   mockConfig.TrackedPodIP,
			MarkedRemoteIPForHostTraffic: mockConfig.TrackedWorldIP,
		}
		mainTrafficStore = s
	}
	return nil
}

func startHostDevWatcher(ctx context.Context) (error, func()) {
	if !globalConfig.EnableHostTraffic {
		return nil, nil
	}
	p := node_watcher.HostDevWatcherParams{
		ParentLogger:         mainLogger,
		NetLib:               mainNetlib,
		BPFTrafficFactory:    mainTrafficFactory,
		Classifier:           mainClassifier,
		HostDevWatcherConfig: globalConfig.HostDevWatcherConfig,
	}
	w, err := node_watcher.NewHostDevWatcher(p)
	if err != nil {
		return errors.Join(err, ErrStartingHostDevWatcher), nil
	}
	if err := w.Start(ctx); err != nil {
		return errors.Join(err, ErrStartingHostDevWatcher), nil
	}
	closeHostDevWatcher := func() {
		w.Close()
	}
	return nil, closeHostDevWatcher
}

func startNetnsWatcher(ctx context.Context) (error, func()) {
	if !globalConfig.EnablePodTraffic {
		return nil, nil
	}
	p := node_watcher.NetnsWatcherParams{
		ParentLogger:       mainLogger,
		BPFTrafficFactory:  mainTrafficFactory,
		NetnsWatcherConfig: globalConfig.NetnsWatcherConfig,
	}
	w, err := node_watcher.NewNetnsWatcher(p)
	if err != nil {
		return errors.Join(err, ErrStartingNetnsWatcher), nil
	}
	if err := w.Start(ctx); err != nil {
		return errors.Join(err, ErrStartingNetnsWatcher), nil
	}
	closeNetnsWatcher := func() {
		w.Close()
	}
	return nil, closeNetnsWatcher
}

func startPodWatcher() error {
	p := k8s_watcher.PodWatcherParams{
		ParentLogger:     mainLogger,
		Client:           mainMgr.GetClient(),
		Scheme:           mainMgr.GetScheme(),
		Classifier:       mainClassifier,
		PodWatcherConfig: globalConfig.PodWatcherConfig,
	}
	w, err := k8s_watcher.NewPodWatcher(p)
	if err != nil {
		return errors.Join(err, ErrStartingPodWatcher)
	}
	if err := w.SetupWithManager(mainMgr); err != nil {
		return errors.Join(err, ErrStartingPodWatcher)
	}
	return nil
}

func startEpWatcher() error {
	params := k8s_watcher.EpWatcherParams{
		Client:              mainMgr.GetClient(),
		Scheme:              mainMgr.GetScheme(),
		PortExposureChecker: mainPortExposureChecker,
		EpWatcherConfig:     globalConfig.EpWatcherConfig,
	}
	ew := k8s_watcher.NewEpWatcher(params)
	if err := ew.SetupWithManager(mainMgr); err != nil {
		return errors.Join(err, ErrStartingEpWatcher)
	}
	return nil
}

func startIngressWatcher() error {
	params := k8s_watcher.IngressWatcherParams{
		Client:               mainMgr.GetClient(),
		Scheme:               mainMgr.GetScheme(),
		PortExposureChecker:  mainPortExposureChecker,
		IngressWatcherConfig: globalConfig.IngressWatcherConfig,
	}
	iw := k8s_watcher.NewIngressWatcher(params)
	if err := iw.SetupWithManager(mainMgr); err != nil {
		return errors.Join(err, ErrStartingIngressWatcher)
	}
	return nil
}

func startPortExposureChecker() error {
	params := k8s_watcher.PortExposureCheckerParams{
		Client:     mainMgr.GetClient(),
		Scheme:     mainMgr.GetScheme(),
		Classifier: mainClassifier,
	}
	pec := k8s_watcher.NewPortExposureChecker(params)
	mainPortExposureChecker = pec
	return nil
}

func startDebugService() error {
	params := debug.DebugServiceParams{
		ParentLogger:       mainLogger,
		DebugServiceConfig: globalConfig.DebugServiceConfig,
	}
	debugService, err := debug.NewDebugService(params)
	if err != nil {
		return err
	}
	if err := debugService.Start(); err != nil {
		return err
	}
	return nil
}

func printErr(err error) {
	mainLogger.Errorf("%v", err)
}
