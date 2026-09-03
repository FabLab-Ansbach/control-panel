package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BaseURL     string            `yaml:"baseUrl"`
	SecretKey   string            `yaml:"secretKey"`
	AuthConfig  *OIDCAuthConfig   `yaml:"authConfig"`
	Connectors  ConnectorsConfig  `yaml:"connectors"`
	Executors   ExecutorConfig    `yaml:"executors"`
	Permissions PermissionsConfig `yaml:"permissions"`
	// FrontendDir, if set, serves the static GUI from this directory at "/".
	FrontendDir string `yaml:"frontendDir"`
	// ListenAddr is the interface to bind to; empty means all interfaces.
	ListenAddr string `yaml:"listenAddr"`
	// ListenPort defaults to 8090 if unset.
	ListenPort int `yaml:"listenPort"`
}

// OIDCAuthConfig is all the backend needs to be a pure resource server: it
// verifies bearer tokens against the issuer's JWKS. It never talks to the
// token endpoint or holds a client secret — the frontend (and anything else
// calling the API) is its own public OIDC client and fetches its own tokens.
type OIDCAuthConfig struct {
	IssuerURL string `yaml:"issuerUrl" validate:"required"`
	// ClientID is the frontend's public OIDC client ID — also the default
	// accepted token audience.
	ClientID string `yaml:"clientId" validate:"required"`
	// M2MClients lists additional OIDC clients accepted for
	// machine-to-machine callers using the client credentials grant. Each
	// is authorized via `permissions`, exactly like an OIDC group — add an
	// entry keyed by the client_id.
	M2MClients []M2MClientConfig `yaml:"m2mClients"`
}

// M2MClientConfig is one machine-to-machine OIDC client accepted alongside
// the frontend's. In Authentik, a client credentials grant is issued by its
// own Application/Provider, which has its own issuer URL (and audience
// equal to its client_id) — so unlike the frontend, each M2M client needs
// its issuer spelled out too.
type M2MClientConfig struct {
	ClientID  string `yaml:"clientId" validate:"required"`
	IssuerURL string `yaml:"issuerUrl" validate:"required"`
}

// PermissionsConfig maps an OIDC group name to what it may do.
type PermissionsConfig map[string]GroupPermission

type GroupPermission struct {
	// Root grants RW access to every executor, present or future.
	Root      bool                   `yaml:"root"`
	Executors map[string]AccessLevel `yaml:"executors"`
}

type AccessLevel string

const (
	AccessLevelRO AccessLevel = "ro"
	AccessLevelRW AccessLevel = "rw"
)

type ConnectorsConfig map[string]ConnectorDefinition

type ConnectorDefinition interface {
	ConnectorType() string
	SetName(name string)
}

type ConnectorDefinitionFactory func() ConnectorDefinition

type ExecutorConfig map[string]ExecutorDefinition

type ExecutorDefinition interface {
	ExecutorType() string
	SetName(name string)
	GetConnectorName() string
}

type ExecutorDefinitionFactory func() ExecutorDefinition

const ConnectorTypeOPNSense = "opnsense"

const ExecutorTypeOPNSenseAliasToggle = "opnsenseAliasToggle"

var connectorDefinitionFactories = map[string]ConnectorDefinitionFactory{
	ConnectorTypeOPNSense: func() ConnectorDefinition {
		return &OPNSenseConnectorCfg{}
	},
}

var executorDefinitionFactories = map[string]ExecutorDefinitionFactory{
	ExecutorTypeOPNSenseAliasToggle: func() ExecutorDefinition {
		return &OPNSenseAliasToggleExecutorCfg{}
	},
}

type OPNSenseConnectorCfg struct {
	Name      string `yaml:"-" validate:"required"`
	Type      string `yaml:"type" validate:"required"`
	BaseURL   string `yaml:"baseUrl" validate:"required"`
	APIKey    string `yaml:"apiKey" validate:"required"`
	APISecret string `yaml:"apiSecret" validate:"required"`
}

type OPNSenseAliasToggleExecutorCfg struct {
	Name          string `yaml:"-" validate:"required"`
	Type          string `yaml:"type" validate:"required"`
	ConnectorName string `yaml:"connectorName" validate:"required"`
	AliasName     string   `yaml:"aliasName" validate:"required"`
	ToggleValues  []string `yaml:"toggleValues" validate:"required"`
}

func (c *OPNSenseConnectorCfg) ConnectorType() string {
	return ConnectorTypeOPNSense

}

func (c *OPNSenseConnectorCfg) SetName(name string) {
	c.Name = name
}

func (c *OPNSenseAliasToggleExecutorCfg) ExecutorType() string {
	return ExecutorTypeOPNSenseAliasToggle
}

func (c *OPNSenseAliasToggleExecutorCfg) SetName(name string) {
	c.Name = name
}

func (c *OPNSenseAliasToggleExecutorCfg) GetConnectorName() string {
	return c.ConnectorName
}

func LoadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil && err != io.EOF {
		return nil, err
	}

	if err := validateRequiredFields(reflect.ValueOf(config).Elem()); err != nil {
		return nil, err
	}

	if err := validatePermissions(config.Permissions); err != nil {
		return nil, err
	}

	return config, nil
}

func validatePermissions(cfg PermissionsConfig) error {
	for group, permission := range cfg {
		for executor, level := range permission.Executors {
			if level != AccessLevelRO && level != AccessLevelRW {
				return fmt.Errorf("permissions.%s.executors.%s: invalid access level %q, expected %q or %q", group, executor, level, AccessLevelRO, AccessLevelRW)
			}
		}
	}
	return nil
}

type Connector struct{}

func (c *ConnectorsConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("connectors must be a mapping")
	}

	decoded := make(ConnectorsConfig, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		name := keyNode.Value

		if _, exists := decoded[name]; exists {
			return fmt.Errorf("duplicate connector name %q at line %d", name, keyNode.Line)
		}

		typeName, err := findMappingValue(valueNode, "type")
		if err != nil {
			return fmt.Errorf("connectors.%s: %w", name, err)
		}

		factory, ok := connectorDefinitionFactories[typeName]
		if !ok {
			return fmt.Errorf("connectors.%s: unknown type %q", name, typeName)
		}

		definition := factory()
		if err := decodeNodeKnownFields(valueNode, definition); err != nil {
			return fmt.Errorf("connectors.%s: %w", name, err)
		}

		definition.SetName(name)
		decoded[name] = definition
	}

	*c = decoded
	return nil
}

func (e *ExecutorConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("executors must be a mapping")
	}

	decoded := make(ExecutorConfig, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		name := keyNode.Value

		if _, exists := decoded[name]; exists {
			return fmt.Errorf("duplicate executor name %q at line %d", name, keyNode.Line)
		}

		typeName, err := findMappingValue(valueNode, "type")
		if err != nil {
			return fmt.Errorf("executors.%s: %w", name, err)
		}

		factory, ok := executorDefinitionFactories[typeName]
		if !ok {
			return fmt.Errorf("executors.%s: unknown type %q", name, typeName)
		}

		definition := factory()

		if err := decodeNodeKnownFields(valueNode, definition); err != nil {
			return fmt.Errorf("executors.%s: %w", name, err)
		}

		definition.SetName(name)
		decoded[name] = definition
	}

	*e = decoded
	return nil
}

func validateRequiredFields(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}

	for value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Struct:
		typeInfo := value.Type()
		for index := 0; index < value.NumField(); index++ {
			field := typeInfo.Field(index)
			fieldValue := value.Field(index)

			isEmptyCollection := (fieldValue.Kind() == reflect.Slice || fieldValue.Kind() == reflect.Map) && fieldValue.Len() == 0
			if field.Tag.Get("validate") == "required" && (fieldValue.IsZero() || isEmptyCollection) {
				return fmt.Errorf("required config field %q is missing", field.Name)
			}

			if err := validateRequiredFields(fieldValue); err != nil {
				return err
			}
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			if err := validateRequiredFields(value.MapIndex(key)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateRequiredFields(value.Index(index)); err != nil {
				return err
			}
		}
	}

	return nil
}

func decodeNodeKnownFields(node *yaml.Node, out any) error {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	if err := encoder.Encode(node); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}

	decoder := yaml.NewDecoder(&buffer)
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil && err != io.EOF {
		return err
	}

	return nil
}

func findMappingValue(node *yaml.Node, key string) (string, error) {
	if node.Kind != yaml.MappingNode {
		return "", fmt.Errorf("expected mapping node")
	}

	for index := 0; index < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1].Value, nil
		}
	}

	return "", fmt.Errorf("required config field %q is missing", key)
}
