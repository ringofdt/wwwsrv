package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"path/filepath"
	"reflect"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

func HttpWriteTextResult(w http.ResponseWriter, res string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, res)
}

func HttpWriteError(w http.ResponseWriter, res string, httpstatus int) {
	w.WriteHeader(httpstatus)
	fmt.Fprintln(w, res)
}

func HttpWriteJSONResult(w http.ResponseWriter, res interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		panic(err)
	}
}

func JSONReply(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("JSONReply: ", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func JSONStreamReply(response interface{}, w http.ResponseWriter, r *http.Request) {
	if reflect.TypeOf(response).Kind() != reflect.Slice {
		JSONReply(response, w)
		return
	}

	ctx := r.Context()
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Send the initial headers saying we're gonna stream the response.
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	s := reflect.ValueOf(response)
	for i := 0; i < s.Len(); i++ {
		resp := s.Index(i).Interface()
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				log.Error(ctx.Err())
			}
			return
		default:
			// Artificially wait a second between reponses.
			// time.Sleep(time.Second)

			// Send some data.
			json, err := json.Marshal(resp)
			if err != nil {
				log.Error("JSONStreamReply: ", err)
				return
			}
			w.Write(json)
			flusher.Flush()

		}
	}
}

//#######################################################

type HTTPSrvConfig struct {
	ListenAt    string `envconfig:"HTTP_LISTEN" default:":8081"`
	DocRootPath string `envconfig:"HTTP_DOCROOT" default:""`
	PrivKeyPath string `envconfig:"HTTP_PRIKEY" default:""`
	PubKeyPath  string `envconfig:"HTTP_PUBKEY" default:""`
}

// HTTPSrv :
type HTTPSrv struct {
	HTTPSrvConfig
	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}

// NewHTTPSrv :
func NewHTTPSrv(cfg HTTPSrvConfig) *HTTPSrv {
	s := &HTTPSrv{
		HTTPSrvConfig: cfg,
	}
	return s
}

func (s *HTTPSrv) InitKeys() (err error) {

	if s.PrivKeyPath != "" {
		signBytes, err := ioutil.ReadFile(s.PrivKeyPath)
		if err != nil {
			err = fmt.Errorf("err loading private Key: %v", err)
			return err
		}
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
		if err != nil {
			err = fmt.Errorf("err parsing signKey: %v", err)
			return err
		}
		s.SignKey = signKey
	}

	if s.PubKeyPath != "" {
		verifyBytes, err := ioutil.ReadFile(s.PubKeyPath)
		if err != nil {
			err = fmt.Errorf("err loading public Key: %v", err)
			return err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			err = fmt.Errorf("err parsing verifykey: %v", err)
			return err
		}
		s.VerifyKey = verifyKey

	}
	return
}

// RunHTTPSrv :
func (s *HTTPSrv) Serve() {
	var err error
	if err = s.InitKeys(); err != nil {
		log.Fatalf("err init keys: %v", err)
	}

	router := mux.NewRouter()
	s.Register(router)
	if pathDocRoot, err := filepath.Abs(s.DocRootPath); err == nil {
		router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(pathDocRoot+"/static"))))
		router.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir(pathDocRoot+"/css"))))
		router.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir(pathDocRoot+"/js"))))
		router.PathPrefix("/img/").Handler(http.StripPrefix("/img/", http.FileServer(http.Dir(pathDocRoot+"/img"))))
		router.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir(pathDocRoot+"/assets"))))

		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			htmlIndex := pathDocRoot + "/index.html"
			http.ServeFile(w, r, htmlIndex)
		})
	}

	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	hldrs := handlers.CORS(originsOk, headersOk, methodsOk)(router)
	hldrs = handlers.CompressHandler(hldrs)

	log.Info("HTTPSrv is Listening at ", s.ListenAt)
	if err = http.ListenAndServe(s.ListenAt, hldrs); err != nil {
		log.Fatalf("ErrServingHTTP, %v", err)
	}
}

// Register :
func (s *HTTPSrv) Register(router *mux.Router) {

	commonMW := negroni.New()
	if s.VerifyKey != nil {
		jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				// jti := token.Claims.(jwt.MapClaims)["jti"].(string)
				// if reason, isRevoked := tokenMgr.IsRevoked(jti); isRevoked {
				// 	return "", fmt.Errorf("token is revoked: %v", reason)
				// }
				return s.VerifyKey, nil
			},
		})
		commonMW.Use(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext))
	}

	var apiRouter *mux.Router

	apiPrefix := "/api/v1"
	apiRouter = router.PathPrefix(apiPrefix + "/o").Subrouter()
	apiRouter.HandleFunc("/ping", s.Ping).Methods("GET")

	sRouter := mux.NewRouter()
	apiRouter = sRouter.PathPrefix(apiPrefix + "/x").Subrouter().StrictSlash(true)
	apiRouter.HandleFunc("/ping", s.Ping).Methods("GET")

	router.PathPrefix(apiPrefix + "/x").Handler(commonMW.With(
		negroni.Wrap(sRouter),
	))

}

//#######################################################

// Ping :
func (s *HTTPSrv) Ping(w http.ResponseWriter, r *http.Request) {
	res := fmt.Sprintf("pong: %v", time.Now())
	log.Infof("ping: %v", res)
	JSONReply(res, w)
}

//#######################################################

func GetULID() string {
	t := time.Now()
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	tid := ulid.MustNew(ulid.Timestamp(t), entropy)
	return tid.String()
}

// GenToken :
func (s *HTTPSrv) GenToken(tokenID string, validDuration time.Duration) (tokenStr string, err error) {
	log := log.WithFields(logrus.Fields{"func": "GenToken"})
	if s.SignKey == nil {
		err = fmt.Errorf("invlaid sign key")
		return
	}

	if tokenID == "" {
		tokenID = GetULID()
	}
	issueAt := time.Now()
	expireAt := time.Date(issueAt.Year(), issueAt.Month(), issueAt.Day(), 23, 59, 59, 0, issueAt.Location())
	if validDuration > 0 {
		expireAt = issueAt.Add(validDuration)
	}
	token := jwt.New(jwt.SigningMethodRS256)
	claims := make(jwt.MapClaims)
	claims["jti"] = tokenID
	claims["exp"] = expireAt.Unix()
	claims["iat"] = issueAt.Unix()
	token.Claims = claims
	tokenStr, err = token.SignedString(s.SignKey)
	if err != nil {
		log.Error(errors.Wrap(err, "Err Signing token"))
		return
	}
	return
}

// ###########################################################################
