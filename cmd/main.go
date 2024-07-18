package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	cv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/bpf/traffic"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/classifier"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/conf"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/k8s_watcher"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/node/cilium_ccm"
	"github.com/dinoallo/sealos-networkmanager-agent/internal/store"
	"github.com/dinoallo/sealos-networkmanager-agent/mock"
	"github.com/dinoallo/sealos-networkmanager-agent/modules"
	bpfcommon "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/common"
	ciliumbpffs "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/bpf/fs"
	dblib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/db"
	"gitlab.com/dinoallo/sealos-networkmanager-library/pkg/db/mongo"
	loglib "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log"
	zaplog "gitlab.com/dinoallo/sealos-networkmanager-library/pkg/log/zap"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	mainDB                  dblib.DB
	mainClassifier          modules.Classifier
	mainPodTrafficStore     modules.PodTrafficStore
	mainTrafficFactory      modules.BPFTrafficFactory
	mainPortExposureChecker modules.PortExposureChecker

	mainLogger   loglib.Logger
	mainMgr      ctrl.Manager
	globalConfig *conf.GlobalConfig

	ErrInitingGlobalConfig     = errors.New("failed to init the global config")
	ErrStartingDB              = errors.New("failed to start the database")
	ErrStartingTrafficFactory  = errors.New("failed to start the traffic factory")
	ErrStartingCCMWatcher      = errors.New("failed to start the cilium ccm watcher")
	ErrStartingClassifier      = errors.New("failed to start the classifier")
	ErrStartingPodTrafficStore = errors.New("failed to start the pod traffic store")
	ErrStartingCtrlManager     = errors.New("failed to start the ctrl manager")
	ErrCreatingCtrlManager     = errors.New("failed to create the ctrl manager")
	ErrStartingPodWatcher      = errors.New("failed to start the pod watcher")
	ErrStartingEpWatcher       = errors.New("failed to start the ep watcher")
	ErrStartingCepWatcher      = errors.New("failed to start the cep watcher")
	ErrStartingIngressWatcher  = errors.New("failed to start the ingress watcher")

	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cv2.AddToScheme(scheme))
}

func main() {
	mainCtx := ctrl.SetupSignalHandler()
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
	// start the pod traffic store
	if err := startPodTrafficStore(mainCtx); err != nil {
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
	defer closeTF()
	// initialize and start the cep watcher if WatchCiliumEndpoint is set to true
	// if err := startCCMWatcher(mainCtx); err != nil {
	// 	printErr(err)
	// 	return
	// }
	// init the main ctrl manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
	})
	if err != nil {
		printErr(errors.Join(err, ErrCreatingCtrlManager))
		return
	}
	mainMgr = mgr
	if err := startCEPWatcher(mainCtx); err != nil {
		printErr(err)
		return
	}
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
	// start the ctrl manager
	if err := mainMgr.Start(mainCtx); err != nil {
		printErr(errors.Join(err, ErrStartingCtrlManager))
		return
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
		ParentLogger:            mainLogger,
		BPFTrafficFactoryConfig: globalConfig.BPFTrafficFactoryConfig,
		PodTrafficStore:         mainPodTrafficStore,
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

func startCEPWatcher(ctx context.Context) error {
	params := k8s_watcher.CepWatcherParams{
		Client:            mainMgr.GetClient(),
		Scheme:            mainMgr.GetScheme(),
		ParentLogger:      mainLogger,
		BPFTrafficFactory: mainTrafficFactory,
		CepWatcherConfig:  globalConfig.CepWatcherConfig,
	}
	cepw, err := k8s_watcher.NewCepWatcher(params)
	if err != nil {
		return err
	}
	if err := cepw.SetupWithManager(mainMgr); err != nil {
		return errors.Join(err, ErrStartingCepWatcher)
	}
	return nil
}

func startCCMWatcher(ctx context.Context) error {
	ciliumBPFFS := ciliumbpffs.NewCiliumBPFFS(bpfcommon.DefaultCiliumTCRoot)
	p := cilium_ccm.CiliumCCMWatcherParams{
		ParentLogger:           mainLogger,
		CiliumCCMWatcherConfig: globalConfig.CiliumCCMWatcherConfig,
		BPFTrafficFactory:      mainTrafficFactory,
		CiliumBPFFS_:           ciliumBPFFS,
	}
	ccmw, err := cilium_ccm.NewCiliumCCMWatcher(p)
	if err != nil {
		return errors.Join(err, ErrStartingCCMWatcher)
	}
	if err := ccmw.Start(ctx); err != nil {
		return errors.Join(err, ErrStartingCCMWatcher)
	}
	return nil
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

func startPodTrafficStore(ctx context.Context) error {
	config := globalConfig.PodTrafficStoreConfig
	if config.Enabled {
		params := store.PodTrafficStoreParams{
			DB:                    mainDB,
			PodTrafficStoreConfig: config,
		}
		s, err := store.NewPodTrafficStore(params)
		if err != nil {
			return errors.Join(err, ErrStartingPodTrafficStore)
		}
		mainPodTrafficStore = s
		if err := s.Start(ctx); err != nil {
			return errors.Join(err, ErrStartingPodTrafficStore)
		}
	} else {
		mockConfig := globalConfig.MockConfig
		s := mock.NewDummyPodTrafficStore(mockConfig.TrackedPodIP)
		mainPodTrafficStore = s
	}
	return nil
}

func startPodWatcher() error {
	p := k8s_watcher.PodWatcherParams{
		ParentLogger: mainLogger,
		Client:       mainMgr.GetClient(),
		Scheme:       mainMgr.GetScheme(),
		Classifier:   mainClassifier,
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
	}
	ew := k8s_watcher.NewEpWatcher(params)
	if err := ew.SetupWithManager(mainMgr); err != nil {
		return errors.Join(err, ErrStartingEpWatcher)
	}
	return nil
}

func startIngressWatcher() error {
	params := k8s_watcher.IngressWatcherParams{
		Client:              mainMgr.GetClient(),
		Scheme:              mainMgr.GetScheme(),
		PortExposureChecker: mainPortExposureChecker,
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

func printErr(err error) {
	mainLogger.Errorf("%v", err)
}
