package main

import (
	"regexp"
	"sync"
	"time"

	"github.com/lonelycode/osin"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/mgo.v2/bson"
)

type UserPolicy struct {
	MID                bson.ObjectId `bson:"_id,omitempty"        json:"_id"`
	ID                 string        `bson:"id,omitempty"         json:"id"`
	Name               string        `bson:"name"                 json:"name"`
	OrgID              string        `bson:"org_id"               json:"org_id"`
	Rate               float64       `bson:"rate"                 json:"rate"`
	Per                float64       `bson:"per"                  json:"per"`
	QuotaMax           int64         `bson:"quota_max"            json:"quota_max"`
	QuotaRenewalRate   int64         `bson:"quota_renewal_rate"   json:"quota_renewal_rate"`
	ThrottleInterval   float64       `bson:"throttle_interval"    json:"throttle_interval"`
	ThrottleRetryLimit int           `bson:"throttle_retry_limit" json:"throttle_retry_limit"`
	MaxQueryDepth      int           `bson:"max_query_depth"      json:"max_query_depth"`
	// AccessRights                  map[string]AccessDefinition      `bson:"access_rights"         json:"access_rights"`
	HMACEnabled                   bool     `bson:"hmac_enabled"         json:"hmac_enabled"`
	EnableHTTPSignatureValidation bool     `                            json:"enable_http_signature_validation" msg:"enable_http_signature_validation"`
	Active                        bool     `bson:"active"               json:"active"`
	IsInactive                    bool     `bson:"is_inactive"          json:"is_inactive"`
	Tags                          []string `bson:"tags"                 json:"tags"`
	KeyExpiresIn                  int64    `bson:"key_expires_in"       json:"key_expires_in"`
	// Partitions                    PolicyPartitions                 `bson:"partitions"            json:"partitions"`
	LastUpdated string                 `bson:"last_updated"         json:"last_updated"`
	MetaData    map[string]interface{} `bson:"meta_data"            json:"meta_data"`
	// GraphQL                       map[string]GraphAccessDefinition `bson:"graphql_access_rights" json:"graphql_access_rights"`
}

type DBAccessDefinition struct {
	APIName     string       `json:"apiname"`
	APIID       string       `json:"apiid"`
	Versions    []string     `json:"versions"`
	AllowedURLs []AccessSpec `json:"allowed_urls" bson:"allowed_urls"` // mapped string MUST be a valid regex
	// RestrictedTypes   []graphql.Type               `json:"restricted_types"`
	// FieldAccessRights []user.FieldAccessDefinition `json:"field_access_rights"`
	Limit *APILimit `json:"limit"`
}

type AccessDefinition struct {
	APIName     string       `json:"api_name"     msg:"api_name"`
	APIID       string       `json:"api_id"       msg:"api_id"`
	Versions    []string     `json:"versions"     msg:"versions"`
	AllowedURLs []AccessSpec `json:"allowed_urls" msg:"allowed_urls" bson:"allowed_urls"` // mapped string MUST be a valid regex
	// RestrictedTypes   []graphql.Type          `json:"restricted_types" msg:"restricted_types"`
	Limit APILimit `json:"limit"        msg:"limit"`
	// FieldAccessRights []FieldAccessDefinition `json:"field_access_rights" msg:"field_access_rights"`

	AllowanceScope string `json:"allowance_scope" msg:"allowance_scope"`
}

type APILimit struct {
	Rate               float64 `json:"rate"                 msg:"rate"`
	Per                float64 `json:"per"                  msg:"per"`
	ThrottleInterval   float64 `json:"throttle_interval"    msg:"throttle_interval"`
	ThrottleRetryLimit int     `json:"throttle_retry_limit" msg:"throttle_retry_limit"`
	MaxQueryDepth      int     `json:"max_query_depth"      msg:"max_query_depth"`
	QuotaMax           int64   `json:"quota_max"            msg:"quota_max"`
	QuotaRenews        int64   `json:"quota_renews"         msg:"quota_renews"`
	QuotaRemaining     int64   `json:"quota_remaining"      msg:"quota_remaining"`
	QuotaRenewalRate   int64   `json:"quota_renewal_rate"   msg:"quota_renewal_rate"`
	SetBy              string  `json:"-"                    msg:"-"`
}

// AccessSpecs define what URLS a user has access to an what methods are enabled
type AccessSpec struct {
	URL     string   `json:"url"     msg:"url"`
	Methods []string `json:"methods" msg:"methods"`
}

type DBPolicy struct {
	Policy       UserPolicy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

type OIDProviderConfig struct {
	Issuer    string            `bson:"issuer"     json:"issuer"`
	ClientIDs map[string]string `bson:"client_ids" json:"client_ids"`
}

type OpenIDOptions struct {
	Providers         []OIDProviderConfig `bson:"providers"           json:"providers"`
	SegregateByClient bool                `bson:"segregate_by_client" json:"segregate_by_client"`
}

type SignatureConfig struct {
	Algorithm        string `mapstructure:"algorithm"          bson:"algorithm"          json:"algorithm"`
	Header           string `mapstructure:"header"             bson:"header"             json:"header"`
	UseParam         bool   `mapstructure:"use_param"          bson:"use_param"          json:"use_param"`
	ParamName        string `mapstructure:"param_name"         bson:"param_name"         json:"param_name"`
	Secret           string `mapstructure:"secret"             bson:"secret"             json:"secret"`
	AllowedClockSkew int64  `mapstructure:"allowed_clock_skew" bson:"allowed_clock_skew" json:"allowed_clock_skew"`
	ErrorCode        int    `mapstructure:"error_code"         bson:"error_code"         json:"error_code"`
	ErrorMessage     string `mapstructure:"error_message"      bson:"error_message"      json:"error_message"`
}

type AuthConfig struct {
	UseParam          bool            `mapstructure:"use_param"          bson:"use_param"          json:"use_param"`
	ParamName         string          `mapstructure:"param_name"         bson:"param_name"         json:"param_name"`
	UseCookie         bool            `mapstructure:"use_cookie"         bson:"use_cookie"         json:"use_cookie"`
	CookieName        string          `mapstructure:"cookie_name"        bson:"cookie_name"        json:"cookie_name"`
	AuthHeaderName    string          `mapstructure:"auth_header_name"   bson:"auth_header_name"   json:"auth_header_name"`
	UseCertificate    bool            `mapstructure:"use_certificate"    bson:"use_certificate"    json:"use_certificate"`
	ValidateSignature bool            `mapstructure:"validate_signature" bson:"validate_signature" json:"validate_signature"`
	Signature         SignatureConfig `mapstructure:"signature"          bson:"signature"          json:"signature,omitempty"`
}

type NotificationsManager struct {
	SharedSecret      string `bson:"shared_secret"          json:"shared_secret"`
	OAuthKeyChangeURL string `bson:"oauth_on_keychange_url" json:"oauth_on_keychange_url"`
}

type RequestSigningMeta struct {
	IsEnabled       bool     `bson:"is_enabled"       json:"is_enabled"`
	Secret          string   `bson:"secret"           json:"secret"`
	KeyId           string   `bson:"key_id"           json:"key_id"`
	Algorithm       string   `bson:"algorithm"        json:"algorithm"`
	HeaderList      []string `bson:"header_list"      json:"header_list"`
	CertificateId   string   `bson:"certificate_id"   json:"certificate_id"`
	SignatureHeader string   `bson:"signature_header" json:"signature_header"`
}

type AuthTypeEnum string

type EndpointMethodAction string

type EndpointMethodMeta struct {
	Action  EndpointMethodAction `bson:"action"  json:"action"`
	Code    int                  `bson:"code"    json:"code"`
	Data    string               `bson:"data"    json:"data"`
	Headers map[string]string    `bson:"headers" json:"headers"`
}

type EndPointMeta struct {
	Path          string                        `bson:"path"           json:"path"`
	IgnoreCase    bool                          `bson:"ignore_case"    json:"ignore_case"`
	MethodActions map[string]EndpointMethodMeta `bson:"method_actions" json:"method_actions"`
}

type CacheMeta struct {
	Method                 string `bson:"method"               json:"method"`
	Path                   string `bson:"path"                 json:"path"`
	CacheKeyRegex          string `bson:"cache_key_regex"      json:"cache_key_regex"`
	CacheOnlyResponseCodes []int  `bson:"cache_response_codes" json:"cache_response_codes"`
}

type RequestInputType string

type TemplateMode string

type TemplateData struct {
	Input          RequestInputType `bson:"input_type"      json:"input_type"`
	Mode           TemplateMode     `bson:"template_mode"   json:"template_mode"`
	EnableSession  bool             `bson:"enable_session"  json:"enable_session"`
	TemplateSource string           `bson:"template_source" json:"template_source"`
}

type TemplateMeta struct {
	TemplateData TemplateData `bson:"template_data" json:"template_data"`
	Path         string       `bson:"path"          json:"path"`
	Method       string       `bson:"method"        json:"method"`
}

type TransformJQMeta struct {
	Filter string `bson:"filter" json:"filter"`
	Path   string `bson:"path"   json:"path"`
	Method string `bson:"method" json:"method"`
}

type HeaderInjectionMeta struct {
	DeleteHeaders []string          `bson:"delete_headers" json:"delete_headers"`
	AddHeaders    map[string]string `bson:"add_headers"    json:"add_headers"`
	Path          string            `bson:"path"           json:"path"`
	Method        string            `bson:"method"         json:"method"`
	ActOnResponse bool              `bson:"act_on"         json:"act_on"`
}

type HardTimeoutMeta struct {
	Path    string `bson:"path"    json:"path"`
	Method  string `bson:"method"  json:"method"`
	TimeOut int    `bson:"timeout" json:"timeout"`
}

type CircuitBreakerMeta struct {
	Path                 string  `bson:"path"                    json:"path"`
	Method               string  `bson:"method"                  json:"method"`
	ThresholdPercent     float64 `bson:"threshold_percent"       json:"threshold_percent"`
	Samples              int64   `bson:"samples"                 json:"samples"`
	ReturnToServiceAfter int     `bson:"return_to_service_after" json:"return_to_service_after"`
	DisableHalfOpenState bool    `bson:"disable_half_open_state" json:"disable_half_open_state"`
}

type RoutingTriggerOnType string

type StringRegexMap struct {
	MatchPattern string `bson:"match_rx" json:"match_rx"`
	Reverse      bool   `bson:"reverse"  json:"reverse"`
	matchRegex   *regexp.Regexp
}

type RoutingTriggerOptions struct {
	HeaderMatches         map[string]StringRegexMap `bson:"header_matches"          json:"header_matches"`
	QueryValMatches       map[string]StringRegexMap `bson:"query_val_matches"       json:"query_val_matches"`
	PathPartMatches       map[string]StringRegexMap `bson:"path_part_matches"       json:"path_part_matches"`
	SessionMetaMatches    map[string]StringRegexMap `bson:"session_meta_matches"    json:"session_meta_matches"`
	RequestContextMatches map[string]StringRegexMap `bson:"request_context_matches" json:"request_context_matches"`
	PayloadMatches        StringRegexMap            `bson:"payload_matches"         json:"payload_matches"`
}

type RoutingTrigger struct {
	On        RoutingTriggerOnType  `bson:"on"         json:"on"`
	Options   RoutingTriggerOptions `bson:"options"    json:"options"`
	RewriteTo string                `bson:"rewrite_to" json:"rewrite_to"`
}

type URLRewriteMeta struct {
	Path         string           `bson:"path"          json:"path"`
	Method       string           `bson:"method"        json:"method"`
	MatchPattern string           `bson:"match_pattern" json:"match_pattern"`
	RewriteTo    string           `bson:"rewrite_to"    json:"rewrite_to"`
	Triggers     []RoutingTrigger `bson:"triggers"      json:"triggers"`
	MatchRegexp  *regexp.Regexp   `                     json:"-"`
}

type VirtualMeta struct {
	ResponseFunctionName string `bson:"response_function_name" json:"response_function_name"`
	FunctionSourceType   string `bson:"function_source_type"   json:"function_source_type"`
	FunctionSourceURI    string `bson:"function_source_uri"    json:"function_source_uri"`
	Path                 string `bson:"path"                   json:"path"`
	Method               string `bson:"method"                 json:"method"`
	UseSession           bool   `bson:"use_session"            json:"use_session"`
	ProxyOnError         bool   `bson:"proxy_on_error"         json:"proxy_on_error"`
}

type RequestSizeMeta struct {
	Path      string `bson:"path"       json:"path"`
	Method    string `bson:"method"     json:"method"`
	SizeLimit int64  `bson:"size_limit" json:"size_limit"`
}

type MethodTransformMeta struct {
	Path     string `bson:"path"      json:"path"`
	Method   string `bson:"method"    json:"method"`
	ToMethod string `bson:"to_method" json:"to_method"`
}

type TrackEndpointMeta struct {
	Path   string `bson:"path"   json:"path"`
	Method string `bson:"method" json:"method"`
}

type ValidatePathMeta struct {
	Path        string                  `bson:"path"                json:"path"`
	Method      string                  `bson:"method"              json:"method"`
	Schema      map[string]interface{}  `bson:"schema"              json:"schema"`
	SchemaB64   string                  `bson:"schema_b64"          json:"schema_b64,omitempty"`
	SchemaCache gojsonschema.JSONLoader `bson:"-"                   json:"-"`
	// Allows override of default 422 Unprocessible Entity response code for validation errors.
	ErrorResponseCode int `bson:"error_response_code" json:"error_response_code"`
}

type InternalMeta struct {
	Path   string `bson:"path"   json:"path"`
	Method string `bson:"method" json:"method"`
}

type GoPluginMeta struct {
	Path       string `bson:"path"        json:"path"`
	Method     string `bson:"method"      json:"method"`
	PluginPath string `bson:"plugin_path" json:"plugin_path"`
	SymbolName string `bson:"func_name"   json:"func_name"`
}

type ExtendedPathsSet struct {
	Ignored                 []EndPointMeta        `bson:"ignored"                    json:"ignored,omitempty"`
	WhiteList               []EndPointMeta        `bson:"white_list"                 json:"white_list,omitempty"`
	BlackList               []EndPointMeta        `bson:"black_list"                 json:"black_list,omitempty"`
	Cached                  []string              `bson:"cache"                      json:"cache,omitempty"`
	AdvanceCacheConfig      []CacheMeta           `bson:"advance_cache_config"       json:"advance_cache_config,omitempty"`
	Transform               []TemplateMeta        `bson:"transform"                  json:"transform,omitempty"`
	TransformResponse       []TemplateMeta        `bson:"transform_response"         json:"transform_response,omitempty"`
	TransformJQ             []TransformJQMeta     `bson:"transform_jq"               json:"transform_jq,omitempty"`
	TransformJQResponse     []TransformJQMeta     `bson:"transform_jq_response"      json:"transform_jq_response,omitempty"`
	TransformHeader         []HeaderInjectionMeta `bson:"transform_headers"          json:"transform_headers,omitempty"`
	TransformResponseHeader []HeaderInjectionMeta `bson:"transform_response_headers" json:"transform_response_headers,omitempty"`
	HardTimeouts            []HardTimeoutMeta     `bson:"hard_timeouts"              json:"hard_timeouts,omitempty"`
	CircuitBreaker          []CircuitBreakerMeta  `bson:"circuit_breakers"           json:"circuit_breakers,omitempty"`
	URLRewrite              []URLRewriteMeta      `bson:"url_rewrites"               json:"url_rewrites,omitempty"`
	Virtual                 []VirtualMeta         `bson:"virtual"                    json:"virtual,omitempty"`
	SizeLimit               []RequestSizeMeta     `bson:"size_limits"                json:"size_limits,omitempty"`
	MethodTransforms        []MethodTransformMeta `bson:"method_transforms"          json:"method_transforms,omitempty"`
	TrackEndpoints          []TrackEndpointMeta   `bson:"track_endpoints"            json:"track_endpoints,omitempty"`
	DoNotTrackEndpoints     []TrackEndpointMeta   `bson:"do_not_track_endpoints"     json:"do_not_track_endpoints,omitempty"`
	ValidateJSON            []ValidatePathMeta    `bson:"validate_json"              json:"validate_json,omitempty"`
	Internal                []InternalMeta        `bson:"internal"                   json:"internal,omitempty"`
	GoPlugin                []GoPluginMeta        `bson:"go_plugin"                  json:"go_plugin,omitempty"`
}

type VersionInfo struct {
	Name      string    `bson:"name"                           json:"name"`
	Expires   string    `bson:"expires"                        json:"expires"`
	ExpiresTs time.Time `bson:"-"                              json:"-"`
	Paths     struct {
		Ignored   []string `bson:"ignored" json:"ignored"`
		WhiteList []string `bson:"white_list" json:"white_list"`
		BlackList []string `bson:"black_list" json:"black_list"`
	} `bson:"paths"                          json:"paths"`
	UseExtendedPaths            bool              `bson:"use_extended_paths"             json:"use_extended_paths"`
	ExtendedPaths               ExtendedPathsSet  `bson:"extended_paths"                 json:"extended_paths"`
	GlobalHeaders               map[string]string `bson:"global_headers"                 json:"global_headers"`
	GlobalHeadersRemove         []string          `bson:"global_headers_remove"          json:"global_headers_remove"`
	GlobalResponseHeaders       map[string]string `bson:"global_response_headers"        json:"global_response_headers"`
	GlobalResponseHeadersRemove []string          `bson:"global_response_headers_remove" json:"global_response_headers_remove"`
	IgnoreEndpointCase          bool              `bson:"ignore_endpoint_case"           json:"ignore_endpoint_case"`
	GlobalSizeLimit             int64             `bson:"global_size_limit"              json:"global_size_limit"`
	OverrideTarget              string            `bson:"override_target"                json:"override_target"`
}

type CheckCommand struct {
	Name    string `bson:"name"    json:"name"`
	Message string `bson:"message" json:"message"`
}

type HostCheckObject struct {
	CheckURL            string            `bson:"url"                   json:"url"`
	Protocol            string            `bson:"protocol"              json:"protocol"`
	Timeout             time.Duration     `bson:"timeout"               json:"timeout"`
	EnableProxyProtocol bool              `bson:"enable_proxy_protocol" json:"enable_proxy_protocol"`
	Commands            []CheckCommand    `bson:"commands"              json:"commands"`
	Method              string            `bson:"method"                json:"method"`
	Headers             map[string]string `bson:"headers"               json:"headers"`
	Body                string            `bson:"body"                  json:"body"`
}

type ServiceDiscoveryConfiguration struct {
	UseDiscoveryService bool   `bson:"use_discovery_service" json:"use_discovery_service"`
	QueryEndpoint       string `bson:"query_endpoint"        json:"query_endpoint"`
	UseNestedQuery      bool   `bson:"use_nested_query"      json:"use_nested_query"`
	ParentDataPath      string `bson:"parent_data_path"      json:"parent_data_path"`
	DataPath            string `bson:"data_path"             json:"data_path"`
	PortDataPath        string `bson:"port_data_path"        json:"port_data_path"`
	TargetPath          string `bson:"target_path"           json:"target_path"`
	UseTargetList       bool   `bson:"use_target_list"       json:"use_target_list"`
	CacheTimeout        int64  `bson:"cache_timeout"         json:"cache_timeout"`
	EndpointReturnsList bool   `bson:"endpoint_returns_list" json:"endpoint_returns_list"`
}

type UptimeTests struct {
	CheckList []HostCheckObject `bson:"check_list" json:"check_list"`
	Config    struct {
		ExpireUptimeAnalyticsAfter int64                         `bson:"expire_utime_after" json:"expire_utime_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
		ServiceDiscovery           ServiceDiscoveryConfiguration `bson:"service_discovery" json:"service_discovery"`
		RecheckWait                int                           `bson:"recheck_wait" json:"recheck_wait"`
	} `bson:"config"     json:"config"`
}

type HostList struct {
	hMutex sync.RWMutex
	hosts  []string
}

type ProxyConfig struct {
	PreserveHostHeader          bool                          `bson:"preserve_host_header"            json:"preserve_host_header"`
	ListenPath                  string                        `bson:"listen_path"                     json:"listen_path"`
	TargetURL                   string                        `bson:"target_url"                      json:"target_url"`
	DisableStripSlash           bool                          `bson:"disable_strip_slash"             json:"disable_strip_slash"`
	StripListenPath             bool                          `bson:"strip_listen_path"               json:"strip_listen_path"`
	EnableLoadBalancing         bool                          `bson:"enable_load_balancing"           json:"enable_load_balancing"`
	Targets                     []string                      `bson:"target_list"                     json:"target_list"`
	StructuredTargetList        *HostList                     `bson:"-"                               json:"-"`
	CheckHostAgainstUptimeTests bool                          `bson:"check_host_against_uptime_tests" json:"check_host_against_uptime_tests"`
	ServiceDiscovery            ServiceDiscoveryConfiguration `bson:"service_discovery"               json:"service_discovery"`
	Transport                   struct {
		SSLInsecureSkipVerify   bool     `bson:"ssl_insecure_skip_verify" json:"ssl_insecure_skip_verify"`
		SSLCipherSuites         []string `bson:"ssl_ciphers" json:"ssl_ciphers"`
		SSLMinVersion           uint16   `bson:"ssl_min_version" json:"ssl_min_version"`
		SSLMaxVersion           uint16   `bson:"ssl_max_version" json:"ssl_max_version"`
		SSLForceCommonNameCheck bool     `json:"ssl_force_common_name_check"`
		ProxyURL                string   `bson:"proxy_url" json:"proxy_url"`
	} `bson:"transport"                       json:"transport"`
}

type MiddlewareDefinition struct {
	Name           string `bson:"name"            json:"name"`
	Path           string `bson:"path"            json:"path"`
	RequireSession bool   `bson:"require_session" json:"require_session"`
	RawBodyOnly    bool   `bson:"raw_body_only"   json:"raw_body_only"`
}

type MiddlewareDriver string
type IdExtractorSource string
type IdExtractorType string
type MiddlewareIdExtractor struct {
	ExtractFrom     IdExtractorSource      `bson:"extract_from"     json:"extract_from"`
	ExtractWith     IdExtractorType        `bson:"extract_with"     json:"extract_with"`
	ExtractorConfig map[string]interface{} `bson:"extractor_config" json:"extractor_config"`
	Extractor       interface{}            `bson:"-"                json:"-"`
}

type MiddlewareSection struct {
	Pre         []MiddlewareDefinition `bson:"pre"           json:"pre"`
	Post        []MiddlewareDefinition `bson:"post"          json:"post"`
	PostKeyAuth []MiddlewareDefinition `bson:"post_key_auth" json:"post_key_auth"`
	AuthCheck   MiddlewareDefinition   `bson:"auth_check"    json:"auth_check"`
	Response    []MiddlewareDefinition `bson:"response"      json:"response"`
	Driver      MiddlewareDriver       `bson:"driver"        json:"driver"`
	IdExtractor MiddlewareIdExtractor  `bson:"id_extractor"  json:"id_extractor"`
}

type CacheOptions struct {
	CacheTimeout               int64    `bson:"cache_timeout"                 json:"cache_timeout"`
	EnableCache                bool     `bson:"enable_cache"                  json:"enable_cache"`
	CacheAllSafeRequests       bool     `bson:"cache_all_safe_requests"       json:"cache_all_safe_requests"`
	CacheOnlyResponseCodes     []int    `bson:"cache_response_codes"          json:"cache_response_codes"`
	EnableUpstreamCacheControl bool     `bson:"enable_upstream_cache_control" json:"enable_upstream_cache_control"`
	CacheControlTTLHeader      string   `bson:"cache_control_ttl_header"      json:"cache_control_ttl_header"`
	CacheByHeaders             []string `bson:"cache_by_headers"              json:"cache_by_headers"`
}

type AuthProviderCode string

type StorageEngineCode string

type AuthProviderMeta struct {
	Name          AuthProviderCode       `bson:"name"           json:"name"`
	StorageEngine StorageEngineCode      `bson:"storage_engine" json:"storage_engine"`
	Meta          map[string]interface{} `bson:"meta"           json:"meta"`
}

type SessionProviderCode string

type SessionProviderMeta struct {
	Name          SessionProviderCode    `bson:"name"           json:"name"`
	StorageEngine StorageEngineCode      `bson:"storage_engine" json:"storage_engine"`
	Meta          map[string]interface{} `bson:"meta"           json:"meta"`
}

type TykEvent string

type TykEventHandlerName string

type EventHandlerTriggerConfig struct {
	Handler     TykEventHandlerName    `bson:"handler_name" json:"handler_name"`
	HandlerMeta map[string]interface{} `bson:"handler_meta" json:"handler_meta"`
}

type EventHandlerMetaConfig struct {
	Events map[TykEvent][]EventHandlerTriggerConfig `bson:"events" json:"events"`
}

type ResponseProcessor struct {
	Name    string      `bson:"name"    json:"name"`
	Options interface{} `bson:"options" json:"options"`
}

type CORSConfig struct {
	Enable             bool     `bson:"enable"              json:"enable"`
	AllowedOrigins     []string `bson:"allowed_origins"     json:"allowed_origins"`
	AllowedMethods     []string `bson:"allowed_methods"     json:"allowed_methods"`
	AllowedHeaders     []string `bson:"allowed_headers"     json:"allowed_headers"`
	ExposedHeaders     []string `bson:"exposed_headers"     json:"exposed_headers"`
	AllowCredentials   bool     `bson:"allow_credentials"   json:"allow_credentials"`
	MaxAge             int      `bson:"max_age"             json:"max_age"`
	OptionsPassthrough bool     `bson:"options_passthrough" json:"options_passthrough"`
	Debug              bool     `bson:"debug"               json:"debug"`
}

type GlobalRateLimit struct {
	Rate float64 `bson:"rate" json:"rate"`
	Per  float64 `bson:"per"  json:"per"`
}

type APIDefinition struct {
	Id                  bson.ObjectId `bson:"_id,omitempty"                  json:"id,omitempty"                             gorm:"primaryKey;column:_id"`
	Name                string        `bson:"name"                           json:"name,omitempty"`
	Slug                string        `bson:"slug"                           json:"slug,omitempty"`
	ListenPort          int           `bson:"listen_port"                    json:"listen_port,omitempty"`
	Protocol            string        `bson:"protocol"                       json:"protocol,omitempty"`
	EnableProxyProtocol bool          `bson:"enable_proxy_protocol"          json:"enable_proxy_protocol,omitempty"`
	APIID               string        `bson:"api_id"                         json:"api_id,omitempty"`
	OrgID               string        `bson:"org_id"                         json:"org_id,omitempty"`
	UseKeylessAccess    bool          `bson:"use_keyless"                    json:"use_keyless,omitempty"`
	UseOauth2           bool          `bson:"use_oauth2"                     json:"use_oauth2,omitempty"`
	UseOpenID           bool          `bson:"use_openid"                     json:"use_openid,omitempty"`
	OpenIDOptions       OpenIDOptions `bson:"openid_options"                 json:"openid_options,omitempty"`
	Oauth2Meta          struct {
		AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types,omitempty"`
		AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types,omitempty"`
		AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect,omitempty"`
	} `bson:"oauth_meta"                     json:"oauth_meta,omitempty"`
	Auth         AuthConfig            `bson:"auth"                           json:"auth,omitempty"` // Deprecated: Use AuthConfigs instead.
	AuthConfigs  map[string]AuthConfig `bson:"auth_configs"                   json:"auth_configs,omitempty"`
	UseBasicAuth bool                  `bson:"use_basic_auth"                 json:"use_basic_auth,omitempty"`
	BasicAuth    struct {
		DisableCaching     bool   `bson:"disable_caching" json:"disable_caching,omitempty"`
		CacheTTL           int    `bson:"cache_ttl" json:"cache_ttl,omitempty"`
		ExtractFromBody    bool   `bson:"extract_from_body" json:"extract_from_body,omitempty"`
		BodyUserRegexp     string `bson:"body_user_regexp" json:"body_user_regexp,omitempty"`
		BodyPasswordRegexp string `bson:"body_password_regexp" json:"body_password_regexp,omitempty"`
	} `bson:"basic_auth"                     json:"basic_auth,omitempty"`
	UseMutualTLSAuth           bool                 `bson:"use_mutual_tls_auth"            json:"use_mutual_tls_auth,omitempty"`
	ClientCertificates         []string             `bson:"client_certificates"            json:"client_certificates,omitempty"`
	UpstreamCertificates       map[string]string    `bson:"upstream_certificates"          json:"upstream_certificates,omitempty"`
	PinnedPublicKeys           map[string]string    `bson:"pinned_public_keys"             json:"pinned_public_keys,omitempty"`
	EnableJWT                  bool                 `bson:"enable_jwt"                     json:"enable_jwt,omitempty"`
	UseStandardAuth            bool                 `bson:"use_standard_auth"              json:"use_standard_auth,omitempty"`
	UseGoPluginAuth            bool                 `bson:"use_go_plugin_auth"             json:"use_go_plugin_auth,omitempty"`
	EnableCoProcessAuth        bool                 `bson:"enable_coprocess_auth"          json:"enable_coprocess_auth,omitempty"`
	JWTSigningMethod           string               `bson:"jwt_signing_method"             json:"jwt_signing_method,omitempty"`
	JWTSource                  string               `bson:"jwt_source"                     json:"jwt_source,omitempty"`
	JWTIdentityBaseField       string               `bson:"jwt_identit_base_field"         json:"jwt_identity_base_field,omitempty"`
	JWTClientIDBaseField       string               `bson:"jwt_client_base_field"          json:"jwt_client_base_field,omitempty"`
	JWTPolicyFieldName         string               `bson:"jwt_policy_field_name"          json:"jwt_policy_field_name,omitempty"`
	JWTDefaultPolicies         []string             `bson:"jwt_default_policies"           json:"jwt_default_policies,omitempty"`
	JWTIssuedAtValidationSkew  uint64               `bson:"jwt_issued_at_validation_skew"  json:"jwt_issued_at_validation_skew,omitempty"`
	JWTExpiresAtValidationSkew uint64               `bson:"jwt_expires_at_validation_skew" json:"jwt_expires_at_validation_skew,omitempty"`
	JWTNotBeforeValidationSkew uint64               `bson:"jwt_not_before_validation_skew" json:"jwt_not_before_validation_skew,omitempty"`
	JWTSkipKid                 bool                 `bson:"jwt_skip_kid"                   json:"jwt_skip_kid,omitempty"`
	JWTScopeToPolicyMapping    map[string]string    `bson:"jwt_scope_to_policy_mapping"    json:"jwt_scope_to_policy_mapping,omitempty"`
	JWTScopeClaimName          string               `bson:"jwt_scope_claim_name"           json:"jwt_scope_claim_name,omitempty"`
	NotificationsDetails       NotificationsManager `bson:"notifications"                  json:"notifications,omitempty"`
	EnableSignatureChecking    bool                 `bson:"enable_signature_checking"      json:"enable_signature_checking,omitempty"`
	HmacAllowedClockSkew       float64              `bson:"hmac_allowed_clock_skew"        json:"hmac_allowed_clock_skew,omitempty"`
	HmacAllowedAlgorithms      []string             `bson:"hmac_allowed_algorithms"        json:"hmac_allowed_algorithms,omitempty"`
	RequestSigning             RequestSigningMeta   `bson:"request_signing"                json:"request_signing,omitempty"`
	BaseIdentityProvidedBy     AuthTypeEnum         `bson:"base_identity_provided_by"      json:"base_identity_provided_by,omitempty"`
	VersionDefinition          struct {
		Location  string `bson:"location" json:"location,omitempty"`
		Key       string `bson:"key" json:"key,omitempty"`
		StripPath bool   `bson:"strip_path" json:"strip_path,omitempty"`
	} `bson:"definition"                     json:"definition,omitempty"`
	VersionData struct {
		NotVersioned   bool                   `bson:"not_versioned" json:"not_versioned,omitempty"`
		DefaultVersion string                 `bson:"default_version" json:"default_version,omitempty"`
		Versions       map[string]VersionInfo `bson:"versions" json:"versions,omitempty"`
	} `bson:"version_data"                   json:"version_data,omitempty"`
	UptimeTests               UptimeTests            `bson:"uptime_tests"                   json:"uptime_tests,omitempty"`
	Proxy                     ProxyConfig            `bson:"proxy"                          json:"proxy,omitempty"`
	DisableRateLimit          bool                   `bson:"disable_rate_limit"             json:"disable_rate_limit,omitempty"`
	DisableQuota              bool                   `bson:"disable_quota"                  json:"disable_quota,omitempty"`
	CustomMiddleware          MiddlewareSection      `bson:"custom_middleware"              json:"custom_middleware,omitempty"`
	CustomMiddlewareBundle    string                 `bson:"custom_middleware_bundle"       json:"custom_middleware_bundle,omitempty"`
	CacheOptions              CacheOptions           `bson:"cache_options"                  json:"cache_options,omitempty"`
	SessionLifetime           int64                  `bson:"session_lifetime"               json:"session_lifetime,omitempty"`
	Active                    bool                   `bson:"active"                         json:"active,omitempty"`
	Internal                  bool                   `bson:"internal"                       json:"internal,omitempty"`
	AuthProvider              AuthProviderMeta       `bson:"auth_provider"                  json:"auth_provider,omitempty"`
	SessionProvider           SessionProviderMeta    `bson:"session_provider"               json:"session_provider,omitempty"`
	EventHandlers             EventHandlerMetaConfig `bson:"event_handlers"                 json:"event_handlers,omitempty"`
	EnableBatchRequestSupport bool                   `bson:"enable_batch_request_support"   json:"enable_batch_request_support,omitempty"`
	EnableIpWhiteListing      bool                   `bson:"enable_ip_whitelisting"         json:"enable_ip_whitelisting,omitempty"                                      mapstructure:"enable_ip_whitelisting"`
	AllowedIPs                []string               `bson:"allowed_ips"                    json:"allowed_ips,omitempty"                                                 mapstructure:"allowed_ips"`
	EnableIpBlacklisting      bool                   `bson:"enable_ip_blacklisting"         json:"enable_ip_blacklisting,omitempty"                                      mapstructure:"enable_ip_blacklisting"`
	BlacklistedIPs            []string               `bson:"blacklisted_ips"                json:"blacklisted_ips,omitempty"                                             mapstructure:"blacklisted_ips"`
	DontSetQuotasOnCreate     bool                   `bson:"dont_set_quota_on_create"       json:"dont_set_quota_on_create,omitempty"                                    mapstructure:"dont_set_quota_on_create"`
	ExpireAnalyticsAfter      int64                  `bson:"expire_analytics_after"         json:"expire_analytics_after,omitempty"                                      mapstructure:"expire_analytics_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	ResponseProcessors        []ResponseProcessor    `bson:"response_processors"            json:"response_processors,omitempty"`
	CORS                      CORSConfig             `bson:"CORS"                           json:"CORS,omitempty"`
	Domain                    string                 `bson:"domain"                         json:"domain,omitempty"`
	Certificates              []string               `bson:"certificates"                   json:"certificates,omitempty"`
	DoNotTrack                bool                   `bson:"do_not_track"                   json:"do_not_track,omitempty"`
	Tags                      []string               `bson:"tags"                           json:"tags,omitempty"`
	EnableContextVars         bool                   `bson:"enable_context_vars"            json:"enable_context_vars,omitempty"`
	ConfigData                map[string]interface{} `bson:"config_data"                    json:"config_data,omitempty"`
	TagHeaders                []string               `bson:"tag_headers"                    json:"tag_headers,omitempty"`
	GlobalRateLimit           GlobalRateLimit        `bson:"global_rate_limit"              json:"global_rate_limit,omitempty"`
	StripAuthData             bool                   `bson:"strip_auth_data"                json:"strip_auth_data,omitempty"`
	EnableDetailedRecording   bool                   `bson:"enable_detailed_recording"      json:"enable_detailed_recording,omitempty"`
	// GraphQL                   GraphQLConfig          `bson:"graphql"                        json:"graphql,omitempty"`
}
